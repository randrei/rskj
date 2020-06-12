/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
 * (derived from ethereumJ library, Copyright (c) 2016 <ether.camp>)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package org.ethereum.vm.program;

import co.rsk.config.VmConfig;
import co.rsk.core.Coin;
import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import co.rsk.pcc.NativeContract;
import co.rsk.peg.Bridge;
import co.rsk.remasc.RemascContract;
import co.rsk.rpc.modules.trace.CallType;
import co.rsk.rpc.modules.trace.CreationData;
import co.rsk.rpc.modules.trace.ProgramSubtrace;
import co.rsk.vm.BitSet;
import com.google.common.annotations.VisibleForTesting;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.config.Constants;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;
import org.ethereum.core.Block;
import org.ethereum.core.BlockFactory;
import org.ethereum.core.Repository;
import org.ethereum.core.Transaction;
import org.ethereum.crypto.HashUtil;
import org.ethereum.util.ByteUtil;
import org.ethereum.util.FastByteComparisons;
import org.ethereum.vm.*;
import org.ethereum.vm.MessageCall.MsgType;
import org.ethereum.vm.PrecompiledContracts.PrecompiledContract;
import org.ethereum.vm.program.invoke.*;
import org.ethereum.vm.program.listener.CompositeProgramListener;
import org.ethereum.vm.program.listener.ProgramListenerAware;
import org.ethereum.vm.trace.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.*;

import static co.rsk.util.ListArrayUtil.*;
import static java.lang.String.format;
import static org.ethereum.util.BIUtil.*;
import static org.ethereum.util.ByteUtil.EMPTY_BYTE_ARRAY;

/**
 * @author Roman Mandeleil
 * @since 01.06.2014
 */
public class Program {
    // These logs should never be in Info mode in production
    private static final Logger logger = LoggerFactory.getLogger("VM");
    private static final Logger gasLogger = LoggerFactory.getLogger("gas");
    private static final Logger rentGasLogger = LoggerFactory.getLogger("rentGas");

    public static final long MAX_MEMORY = (1<<30);

    //Max size for stack checks  //#mish: is this still needed?
    private static final int MAX_STACKSIZE = 1024;

    private final ActivationConfig.ForBlock activations;
    private final Transaction transaction;

    private final ProgramInvoke invoke;
    private final ProgramInvokeFactory programInvokeFactory = new ProgramInvokeFactoryImpl();

    private ProgramOutListener listener;
    private final ProgramTraceListener traceListener;
    private final CompositeProgramListener programListener = new CompositeProgramListener();

    private final Stack stack;
    private final Memory memory;
    private final Storage storage;
    private byte[] returnDataBuffer;

    private final ProgramResult result = new ProgramResult();
    private final ProgramTrace trace;

    private final byte[] ops; // #mish: the ops can be from contract code or Tx.data()
    private int pc;
    private byte lastOp;
    private boolean stopped;
    private byte exeVersion;    // currently limited to 0..127
    private byte scriptVersion; // currently limited to 0..127
    private int startAddr;

    private BitSet jumpdestSet;

    private final VmConfig config;
    private final PrecompiledContracts precompiledContracts;
    private final BlockFactory blockFactory;

    private boolean isLogEnabled;
    private boolean isGasLogEnabled;
    private boolean isRentGasLogEnabled;

    private RskAddress rskOwnerAddress;

    private final Set<DataWord> deletedAccountsInBlock;

    public Program(
            VmConfig config,
            PrecompiledContracts precompiledContracts,
            BlockFactory blockFactory,
            ActivationConfig.ForBlock activations,
            byte[] ops,
            ProgramInvoke programInvoke,
            Transaction transaction,
            Set<DataWord> deletedAccounts) {
        this.config = config;
        this.precompiledContracts = precompiledContracts;
        this.blockFactory = blockFactory;
        this.activations = activations;
        this.transaction = transaction;
        isLogEnabled = logger.isInfoEnabled();
        isGasLogEnabled = gasLogger.isInfoEnabled();
        isRentGasLogEnabled = rentGasLogger.isInfoEnabled();

        if (isLogEnabled ) {
            logger.warn("WARNING! VM logging is enabled. This will make the VM 200 times slower. Do not use in production.");
        }

        if (isGasLogEnabled) {
            gasLogger.warn("WARNING! Gas logging is enabled. This will the make VM 200 times slower. Do not use in production.");
        }

        if (isRentGasLogEnabled) {   // #mish: quantitative impact of adding rent gas logging on VM is unknown
            rentGasLogger.warn("WARNING! Rent gas logging is enabled. This will the make VM orders of magnitude slower. Do not use in production.");
        }

        this.invoke = programInvoke;

        this.ops = nullToEmpty(ops);

        this.trace = createProgramTrace(config, programInvoke);
        this.memory = setupProgramListener(new Memory());
        this.stack = setupProgramListener(new Stack());
        this.stack.ensureCapacity(1024); // faster?
        this.storage = setupProgramListener(new Storage(programInvoke));
        this.deletedAccountsInBlock = new HashSet<>(deletedAccounts);

        precompile();
        traceListener = new ProgramTraceListener(config);
    }

    private static ProgramTrace createProgramTrace(VmConfig config, ProgramInvoke programInvoke) {
        if (!config.vmTrace()) {
            return new EmptyProgramTrace();
        }

        if ((config.vmTraceOptions() & VmConfig.LIGHT_TRACE) != 0) {
            return new SummarizedProgramTrace(programInvoke);
        }

        return new DetailedProgramTrace(config, programInvoke);
    }

    /**
     * Defines the depth of the call stack inside the EVM.
     * Changed to a value more similar to Ethereum's with EIP150
     * since RSKIP150.
     */
    public int getMaxDepth() {
        if (activations.isActive(ConsensusRule.RSKIP150)) {
            return 400;
        }
        return 1024;
    }

    public int getCallDeep() {
        return invoke.getCallDeep();
    }

    private InternalTransaction addInternalTx(byte[] nonce, DataWord gasLimit, RskAddress senderAddress, RskAddress receiveAddress,
                                              Coin value, byte[] data, String note) {
        if (transaction == null) {
            return null;
        }

        byte[] senderNonce = isEmpty(nonce) ? getStorage().getNonce(senderAddress).toByteArray() : nonce;

        return getResult().addInternalTransaction(
                transaction.getHash().getBytes(),
                getCallDeep(),
                senderNonce,
                getGasPrice(),
                gasLimit,
                senderAddress.getBytes(),
                receiveAddress.getBytes(),
                value.getBytes(),
                data,
                note);
    }


    private <T extends ProgramListenerAware> T setupProgramListener(T traceListenerAware) {
        if (programListener.isEmpty()) {
            programListener.addListener(traceListener);
        }

        traceListenerAware.setTraceListener(traceListener);
        return traceListenerAware;
    }

    public byte getOp(int pc) {
        return (getLength(ops) <= pc) ? 0 : ops[pc];
    }

    public byte getCurrentOp() {
        return isEmpty(ops) ? 0 : ops[pc];
    }

    /**
     * Last Op can only be set publicly (no getLastOp method), is used for logging.
     */
    public void setLastOp(byte op) {
        this.lastOp = op;
    }

    private void stackPushZero() {
        stackPush(DataWord.ZERO);
    }

    private void stackPushOne() {
        stackPush(DataWord.ONE);
    }

    private void stackClear(){
        stack.clear();
    }

    public void stackPush(DataWord stackWord) {
        verifyStackOverflow(0, 1); //Sanity Check
        stack.push(stackWord);
    }

    public Stack getStack() {
        return this.stack;
    }

    public int getPC() {
        return pc;
    }

    public void setPC(DataWord pc) {
        this.setPC(pc.intValue());
    }

    public void setPC(int pc) {
        this.pc = pc;

        if (this.pc >= ops.length) {
            stop();
        }
    }

    public boolean isStopped() {
        return stopped;
    }

    public void stop() {
        stopped = true;
    }

    public void setHReturn(byte[] buff) {
        getResult().setHReturn(buff);
    }

    public void step() {
        setPC(pc + 1);
    }


    public DataWord sweepGetDataWord(int n) {
        if (pc + n > ops.length) {
            stop();
            // In this case partial data is copied. At least Ethereumj does this
            // Asummes LSBs are zero. assignDataRange undestands this semantics.
        }

        DataWord dw = DataWord.valueOf(ops, pc, n);
        pc += n;
        if (pc >= ops.length) {
            stop();
        }

        return dw;
    }

    public DataWord stackPop() {
        return stack.pop();
    }

    /**
     * Verifies that the stack is at least <code>stackSize</code>
     *
     * @param stackSize int
     * @throws StackTooSmallException If the stack is
     *                                smaller than <code>stackSize</code>
     */
    public void verifyStackSize(int stackSize) {
        if (stackSize < 0 || stack.size() < stackSize) {
            throw ExceptionHelper.tooSmallStack(stackSize, stack.size());
        }
    }

    public void verifyStackOverflow(int argsReqs, int returnReqs) {
        if ((stack.size() - argsReqs + returnReqs) > MAX_STACKSIZE) {
            throw new StackTooLargeException("Expected: overflow " + MAX_STACKSIZE + " elements stack limit");
        }
    }

    public int getMemSize() {
        return memory.size();
    }

    public void memorySave(DataWord addrB, DataWord value) {
        //
        memory.write(addrB.intValue(), value.getData(), value.getData().length, false);
    }

    private void memorySaveLimited(int addr, byte[] data, int dataSize) {
        memory.write(addr, data, dataSize, true);
    }

    public void memorySave(int addr, byte[] value) {
        memory.write(addr, value, value.length, false);
    }

    public void memoryExpand(DataWord outDataOffs, DataWord outDataSize) {
        if (!outDataSize.isZero()) {
            memory.extend(outDataOffs.intValue(), outDataSize.intValue());
        }
    }

    /**
     * Allocates a piece of memory and stores value at given offset address
     *
     * @param addr      is the offset address
     * @param allocSize size of memory needed to write
     * @param value     the data to write to memory
     */
    public void memorySave(int addr, int allocSize, byte[] value) {
        memory.extendAndWrite(addr, allocSize, value);
    }


    public DataWord memoryLoad(DataWord addr) {
        return memory.readWord(addr.intValue());
    }

    public byte[] memoryChunk(int offset, int size) {
        return memory.read(offset, size);
    }

    /**
     * Allocates extra memory in the program for
     * a specified size, calculated from a given offset
     *
     * @param offset the memory address offset
     * @param size   the number of bytes to allocate
     */
    public void allocateMemory(int offset, int size) {
        memory.extend(offset, size);
    }

    public void suicide(DataWord obtainerAddress) {

        RskAddress owner = getOwnerRskAddress();
        Coin balance = getStorage().getBalance(owner);
        RskAddress obtainer = new RskAddress(obtainerAddress);

        if (!balance.equals(Coin.ZERO)) {
            logger.info("Transfer to: [{}] heritage: [{}]", obtainer, balance);

            addInternalTx(null, null, owner, obtainer, balance, null, "suicide");

            if (FastByteComparisons.compareTo(owner.getBytes(), 0, 20, obtainer.getBytes(), 0, 20) == 0) {
                // if owner == obtainer just zeroing account according to Yellow Paper
                getStorage().addBalance(owner, balance.negate());
            } else {
                getStorage().transfer(owner, obtainer, balance);
            }
        }
        // In any case, remove the account
        // #mish: this simply marks for deletion
        // actual deletion happens at end of TxExecutor (finalization stage) 
        getResult().addDeleteAccount(this.getOwnerAddress());

        SuicideInvoke invoke = new SuicideInvoke(DataWord.valueOf(owner.getBytes()), obtainerAddress, DataWord.valueOf(balance.getBytes()));
        ProgramSubtrace subtrace = ProgramSubtrace.newSuicideSubtrace(invoke);

        getTrace().addSubTrace(subtrace);
    }

    public void send(DataWord destAddress, Coin amount) {

        RskAddress owner = getOwnerRskAddress();
        RskAddress dest = new RskAddress(destAddress);
        Coin balance = getStorage().getBalance(owner);

        if (isNotCovers(balance, amount)) {
            return; // does not do anything.
        }

        if (isLogEnabled) {
            logger.info("Transfer to: [{}] amount: [{}]",
                    dest,
                    amount);
        }

        addInternalTx(null, null, owner, dest, amount, null, "send");

        getStorage().transfer(owner, dest, amount);
    }

    public Repository getStorage() {
        return this.storage;
    }

    @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
    public void createContract(DataWord value, DataWord memStart, DataWord memSize) {
        RskAddress senderAddress = new RskAddress(getOwnerAddress());

        byte[] nonce = getStorage().getNonce(senderAddress).toByteArray();
        byte[] newAddressBytes = HashUtil.calcNewAddr(getOwnerAddress().getLast20Bytes(), nonce);
        RskAddress newAddress = new RskAddress(newAddressBytes);

        createContract(senderAddress, nonce, value, memStart, memSize, newAddress);
    }

    @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
    public void createContract2(DataWord value, DataWord memStart, DataWord memSize, DataWord salt) {
        RskAddress senderAddress = new RskAddress(getOwnerAddress());
        byte[] programCode = memoryChunk(memStart.intValue(), memSize.intValue());

        byte[] newAddressBytes = HashUtil.calcSaltAddr(senderAddress, programCode, salt.getData());
        byte[] nonce = getStorage().getNonce(senderAddress).toByteArray();
        RskAddress newAddress = new RskAddress(newAddressBytes);

        createContract(senderAddress, nonce, value, memStart, memSize, newAddress);
    }

    // #mish contract code is fetched from memory location memStart though memStart + memSize 
    private void createContract( RskAddress senderAddress, byte[] nonce, DataWord value, DataWord memStart, DataWord memSize, RskAddress contractAddress) {
        if (getCallDeep() == getMaxDepth()) {
            logger.debug("max depth reached creating a new contract inside contract run: [{}]", senderAddress);
            stackPushZero();
            return;
        }

        Coin endowment = new Coin(value.getData());
        if (isNotCovers(getStorage().getBalance(senderAddress), endowment)) {
            stackPushZero();
            return;
        }

        // [1] FETCH THE CODE FROM THE MEMORY
        byte[] programCode = memoryChunk(memStart.intValue(), memSize.intValue());

        if (isLogEnabled) {
            logger.info("creating a new contract inside contract run: [{}]", senderAddress);
        }

        //  actual gas subtract
        long gasLimit = getRemainingGas();
        spendGas(gasLimit, "internal call");

        // #mish  rentgaslimit get Remaining for internal call
        //long rentGasLimit = getRemainingRentGas();
        //spendRentGas(rentGasLimit, "internal call");


        if (byTestingSuite()) {
            // This keeps track of the contracts created for a test
            getResult().addCallCreate(programCode, EMPTY_BYTE_ARRAY,
                    gasLimit,
                    value.getNoLeadZeroesData());
        }

        // [3] UPDATE THE NONCE
        // (THIS STAGE IS NOT REVERTED BY ANY EXCEPTION)
        if (!byTestingSuite()) {
            getStorage().increaseNonce(senderAddress);
        }
        // Start tracking repository changes for the constructor of the contract
        Repository track = getStorage().startTracking();

        ProgramResult programResult = ProgramResult.empty();

        if (getActivations().isActive(ConsensusRule.RSKIP125) &&
                deletedAccountsInBlock.contains(DataWord.valueOf(contractAddress.getBytes()))) {
            // Check if the address was previously deleted in the same block

            programResult.setException(ExceptionHelper.addressCollisionException(contractAddress));
            if (isLogEnabled) {
                logger.debug("contract run halted by Exception: contract: [{}], exception: ",
                        contractAddress,
                        programResult.getException());
            }

            track.rollback();
            stackPushZero();

            return;
        }

        //In case of hashing collisions, check for any balance before createAccount()
        if (track.isExist(contractAddress)) {
            // Hashing collisions in CREATE are rare, but in CREATE2 are possible
            // We check for the nonce to non zero and that the code to be not empty
            // if any of this conditions is true, the contract creation fails

            byte[] code = track.getCode(contractAddress);
            boolean hasNonEmptyCode = (code != null && code.length != 0);
            boolean nonZeroNonce = track.getNonce(contractAddress).longValue() != 0;

            if (getActivations().isActive(ConsensusRule.RSKIP125) && (hasNonEmptyCode || nonZeroNonce)) {
                // Contract collision we fail with exactly the same behavior as would arise if
                // the first byte in the init code were an invalid opcode
                programResult.setException(ExceptionHelper.addressCollisionException(contractAddress));
                if (isLogEnabled) {
                    logger.debug("contract run halted by Exception: contract: [{}], exception: ",
                            contractAddress,
                            programResult.getException());
                }

                // The programResult is empty and internalTx was not created so we skip this part
                /*if (internalTx == null) {
                    throw new NullPointerException();
                }

                internalTx.reject();
                programResult.rejectInternalTransactions();
                programResult.rejectLogInfos();*/

                track.rollback();
                stackPushZero();

                return;
            }
            /** #mish if there is an address collision but
             * there is no code or non-0 nonce associated with it, 
             * then it's okay to continue, just preserve any prior balance 
            */ 
            Coin oldBalance = track.getBalance(contractAddress);
            track.createAccount(contractAddress);
            track.addBalance(contractAddress, oldBalance);
        } else {
            track.createAccount(contractAddress);
        }

        track.setupContract(contractAddress);

        if (getActivations().isActive(ConsensusRule.RSKIP125)) {
            track.increaseNonce(contractAddress);
        }

        // [4] TRANSFER THE BALANCE
        track.addBalance(senderAddress, endowment.negate());
        Coin newBalance = Coin.ZERO;
        if (!byTestingSuite()) {
            newBalance = track.addBalance(contractAddress, endowment);
        }


        // [5] COOK THE INVOKE AND EXECUTE
        programResult = getProgramResult(senderAddress, nonce, value, contractAddress, endowment, programCode, gasLimit, track, newBalance, programResult);
        if (programResult == null) {
            return;
        }

        // REFUND THE REMAIN GAS
        refundRemainingGas(gasLimit, programResult);
    }

    private void refundRemainingGas(long gasLimit, ProgramResult programResult) {
        if (programResult.getGasUsed() >= gasLimit) {
            return;
        }
        long refundGas = GasCost.subtract(gasLimit, programResult.getGasUsed());
        refundGas(refundGas, "remaining gas from the internal call");
        if (isGasLogEnabled) {
            gasLogger.info("The remaining gas is refunded, account: [{}], gas: [{}] ",
                    Hex.toHexString(getOwnerAddress().getLast20Bytes()),
                    refundGas
            );
        }
    }

    private ProgramResult getProgramResult(RskAddress senderAddress, byte[] nonce, DataWord value,
                                           RskAddress contractAddress, Coin endowment, byte[] programCode,
                                           long gasLimit, Repository track, Coin newBalance, ProgramResult programResult) {


        InternalTransaction internalTx = addInternalTx(nonce, getGasLimit(), senderAddress, RskAddress.nullAddress(), endowment, programCode, "create");
        ProgramInvoke programInvoke = programInvokeFactory.createProgramInvoke(
                this, DataWord.valueOf(contractAddress.getBytes()), getOwnerAddress(), value, gasLimit,
                newBalance, null, track, this.invoke.getBlockStore(), false, byTestingSuite());

        returnDataBuffer = null; // reset return buffer right before the call

        if (!isEmpty(programCode)) {
            VM vm = new VM(config, precompiledContracts);
            Program program = new Program(config, precompiledContracts, blockFactory, activations, programCode, programInvoke, internalTx, deletedAccountsInBlock);
            vm.play(program);
            programResult = program.getResult();

            if (programResult.getException() == null && !programResult.isRevert()) {
                getTrace().addSubTrace(ProgramSubtrace.newCreateSubtrace(new CreationData(programCode, programResult.getHReturn(), contractAddress), program.getProgramInvoke(), program.getResult(), program.getTrace().getSubtraces()));
            }
        }

        if (programResult.getException() != null || programResult.isRevert()) {
            if (isLogEnabled) {
                logger.debug("contract run halted by Exception: contract: [{}], exception: ",
                        contractAddress,
                        programResult.getException());
            }

            if (internalTx == null) {
                throw new NullPointerException();
            }

            internalTx.reject();
            programResult.rejectInternalTransactions();
            programResult.rejectLogInfos();

            track.rollback();
            stackPushZero();
            if (programResult.getException() != null) {
                return null;
            } else {
                returnDataBuffer = result.getHReturn();
            }
        }
        else {
            // CREATE THE CONTRACT OUT OF RETURN
            byte[] code = programResult.getHReturn();
            int codeLength = getLength(code);

            long storageCost = GasCost.multiply(GasCost.CREATE_DATA, codeLength);
            long afterSpend = programInvoke.getGas() - storageCost - programResult.getGasUsed();

            if (afterSpend < 0) {
                programResult.setException(
                        ExceptionHelper.notEnoughSpendingGas(
                                "No gas to return just created contract",
                                storageCost,
                                this));
            } else if (codeLength > Constants.getMaxContractSize()) {
                programResult.setException(
                        ExceptionHelper.tooLargeContractSize(
                                Constants.getMaxContractSize(),
                                codeLength));
            } else {
                programResult.spendGas(storageCost);
                track.saveCode(contractAddress, code);
            }

            track.commit();

            getResult().addDeleteAccounts(programResult.getDeleteAccounts());
            getResult().addLogInfos(programResult.getLogInfoList());

            // IN SUCCESS PUSH THE ADDRESS INTO THE STACK
            stackPush(DataWord.valueOf(contractAddress.getBytes()));
        }

        return programResult;
    }

    public static long limitToMaxLong(DataWord gas) {
        return gas.longValueSafe();

    }

    public static long limitToMaxLong(BigInteger gas) {
        try {
            long r = gas.longValueExact();
            if (r<0)  // check if this can happen
            {
                return Long.MAX_VALUE;
            }
            return r;
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }

    public static long multiplyLimitToMaxLong(long a,long b) {
        long d;

        try {
            d = Math.multiplyExact(a, b);
        } catch (ArithmeticException e) {
            d = Long.MAX_VALUE;
        }
        return d;
    }

    /**
     * This method is for internal code invocations
     * <p/>
     * - Normal calls invoke a specified contract which updates itself
     * - Stateless calls invoke code from another contract, within the context of the caller
     *
     * @param msg is the message call object of type org.ethereuem.vm.MessageCall
     */
    public void callToAddress(MessageCall msg) {

        if (getCallDeep() == getMaxDepth()) {
            stackPushZero();
            refundGas(msg.getGas().longValue(), " call deep limit reach");
            return;
        }

        byte[] data = memoryChunk(msg.getInDataOffs().intValue(), msg.getInDataSize().intValue());

        // FETCH THE SAVED STORAGE
        RskAddress codeAddress = new RskAddress(msg.getCodeAddress());
        RskAddress senderAddress = getOwnerRskAddress();
        RskAddress contextAddress = msg.getType().isStateless() ? senderAddress : codeAddress;

        if (isLogEnabled) {
            logger.info("{} for existing contract: address: [{}], outDataOffs: [{}], outDataSize: [{}]  ", msg.getType().name(),
                    contextAddress, msg.getOutDataOffs().longValue(), msg.getOutDataSize().longValue());
        }

        Repository track = getStorage().startTracking();

        // 2.1 PERFORM THE VALUE (endowment) PART
        Coin endowment = new Coin(msg.getEndowment().getData());
        Coin senderBalance = track.getBalance(senderAddress);
        if (isNotCovers(senderBalance, endowment)) {
            stackPushZero();
            refundGas(msg.getGas().longValue(), "refund gas from message call");
            return;
        }

        // FETCH THE CODE
        byte[] programCode = getStorage().isExist(codeAddress) ? getStorage().getCode(codeAddress) : EMPTY_BYTE_ARRAY;
        // programCode  can be null

        // Always first remove funds from sender
        track.addBalance(senderAddress, endowment.negate());

        Coin contextBalance;

        if (byTestingSuite()) {
            // This keeps track of the calls created for a test
            getResult().addCallCreate(data, contextAddress.getBytes(),
                    msg.getGas().longValueSafe(),
                    msg.getEndowment().getNoLeadZeroesData());
            return;
        }

        contextBalance = track.addBalance(contextAddress, endowment);

        // CREATE CALL INTERNAL TRANSACTION
        InternalTransaction internalTx = addInternalTx(null, getGasLimit(), senderAddress, contextAddress, endowment, programCode, "call");

        boolean callResult;

        if (!isEmpty(programCode)) {
            callResult = executeCode(msg, contextAddress, contextBalance, internalTx, track, programCode, senderAddress, data);
        }
        else {
            track.commit();
            callResult = true;
            refundGas(GasCost.toGas(msg.getGas().longValue()), "remaining gas from the internal call");

            DataWord callerAddress = DataWord.valueOf(senderAddress.getBytes());
            DataWord ownerAddress = DataWord.valueOf(contextAddress.getBytes());
            DataWord transferValue = DataWord.valueOf(endowment.getBytes());

            TransferInvoke invoke = new TransferInvoke(callerAddress, ownerAddress, msg.getGas().longValue(), transferValue);
            ProgramResult result = new ProgramResult();

            ProgramSubtrace subtrace = ProgramSubtrace.newCallSubtrace(CallType.fromMsgType(msg.getType()), invoke, result, Collections.emptyList());

            getTrace().addSubTrace(subtrace);
        }

        // 4. THE FLAG OF SUCCESS IS ONE PUSHED INTO THE STACK
        if (callResult) {
            stackPushOne();
        }
        else {
            stackPushZero();
        }
    }

    private ProgramInvoke getProgramInvoke() {
        return this.invoke;
    }

    private boolean executeCode(
            MessageCall msg,
            RskAddress contextAddress,
            Coin contextBalance,
            InternalTransaction internalTx,
            Repository track,
            byte[] programCode,
            RskAddress senderAddress,
            byte[] data) {

        returnDataBuffer = null; // reset return buffer right before the call
        ProgramResult childResult;

        ProgramInvoke programInvoke = programInvokeFactory.createProgramInvoke(
                this, DataWord.valueOf(contextAddress.getBytes()),
                msg.getType() == MsgType.DELEGATECALL ? getCallerAddress() : getOwnerAddress(),
                msg.getType() == MsgType.DELEGATECALL ? getCallValue() : msg.getEndowment(),
                limitToMaxLong(msg.getGas()), 
                contextBalance, data, track, this.invoke.getBlockStore(),
                msg.getType() == MsgType.STATICCALL || isStaticCall(), byTestingSuite());

        VM vm = new VM(config, precompiledContracts);
        Program program = new Program(config, precompiledContracts, blockFactory, activations, programCode, programInvoke, internalTx, deletedAccountsInBlock);

        vm.play(program);
        childResult  = program.getResult();

        getTrace().addSubTrace(ProgramSubtrace.newCallSubtrace(CallType.fromMsgType(msg.getType()), program.getProgramInvoke(), program.getResult(), program.getTrace().getSubtraces()));

        getTrace().merge(program.getTrace());
        getResult().merge(childResult);

        boolean childCallSuccessful = true;

        if (childResult.getException() != null || childResult.isRevert()) {
            if (isGasLogEnabled) {
                gasLogger.debug("contract run halted by Exception: contract: [{}], exception: ",
                        contextAddress,
                        childResult.getException());
            }

            internalTx.reject();
            childResult.rejectInternalTransactions();
            childResult.rejectLogInfos();

            track.rollback();
            // when there's an exception we skip applying results and refunding gas,
            // and we only do that when the call is successful or there's a REVERT operation.
            // #mish todo: if there is an exception some rentgas should be refunded?
            // Partial refund of rentgas depends on the exception type of childResult.getException()  
            if (childResult.getException() != null) {    
                return false;
            }

            childCallSuccessful = false;
        } else {
            // 4. THE FLAG OF SUCCESS IS ONE PUSHED INTO THE STACK
            track.commit();
        }


        // 3. APPLY RESULTS: childResult.getHReturn() into out_memory allocated
        byte[] buffer = childResult.getHReturn();
        int offset = msg.getOutDataOffs().intValue();
        int size = msg.getOutDataSize().intValue();

        memorySaveLimited(offset, buffer, size);

        returnDataBuffer = buffer;

        // 5.1 REFUND THE REMAIN GAS
        BigInteger refundGas = msg.getGas().value().subtract(toBI(childResult.getGasUsed()));
        if (isPositive(refundGas)) {
            // Since the original gas transferred was < Long.MAX_VALUE then the refund
            // also fits in a long.
            // SUICIDE refunds 24.000 and SSTORE clear refunds 15.000 gas.
            // The accumulated refund can not exceed half the gas used
            // for the current context (i.e. the initial call)
            // Therefore, the regundGas also fits in a long.
            refundGas(refundGas.longValue(), "remaining gas from the internal call");
            if (isGasLogEnabled) {
                gasLogger.info("The remaining gas refunded, account: [{}], gas: [{}] ", senderAddress, refundGas);
            }
        }

        // 5.2 REFUND REMIAINING STORAGE RENT GAS
        /*BigInteger refundRentGas = msg.getRentGas().value().subtract(toBI(childResult.getRentGasUsed()));
        if (isPositive(refundRentGas)) {
            // Since the original gas transferred was < Long.MAX_VALUE then the refund
            // also fits in a long.
            refundRentGas(refundRentGas.longValue(), "remaining rent gas from the internal call");
            if (isRentGasLogEnabled) {
                rentGasLogger.info("The remaining gas refunded, account: [{}], gas: [{}] ", senderAddress, refundRentGas);
            }
        }*/

        return childCallSuccessful;
    }

    public void spendGas(long gasValue, String cause) {
        if (isGasLogEnabled) {
            gasLogger.info("[{}] Spent for cause: [{}], gas: [{}]", invoke.hashCode(), cause, gasValue);
        }

        if (getRemainingGas()  < gasValue) {
            throw ExceptionHelper.notEnoughSpendingGas(cause, gasValue, this);
        }

        getResult().spendGas(gasValue);
    }

    public void spendRentGas(long rentGasValue, String cause) {
        if (isRentGasLogEnabled) {
            rentGasLogger.info("[{}] Spent for cause: [{}], rentgas: [{}]", invoke.hashCode(), cause, rentGasValue);
        }

        /*if (getRemainingRentGas()  < rentGasValue) {
            throw ExceptionHelper.notEnoughSpendingGas(cause, rentGasValue, this);
        }*/

        getResult().spendRentGas(rentGasValue);
    }

    public void restart() {
        setPC(startAddr);
        stackClear();
        clearUsedGas();
        clearUsedRentGas();
        stopped=false;
    }

    private void clearUsedGas() {
        getResult().clearUsedGas();
    }

    private void clearUsedRentGas() {
        getResult().clearUsedRentGas();
    }

    public void spendAllGas() {
        spendGas(getRemainingGas(), "Spending all remaining");
    }

    /*public void spendAllRentGas() {
        spendRentGas(getRemainingRentGas(), "Spending all remaining rentgas");
    }*/

    private void refundGas(long gasValue, String cause) {
        if (isGasLogEnabled) {
            gasLogger.info("[{}] Refund for cause: [{}], gas: [{}]", invoke.hashCode(), cause, gasValue);
        }
        getResult().refundGas(gasValue);
    }

    private void refundRentGas(long rentGasValue, String cause) {
        if (isRentGasLogEnabled) {
            rentGasLogger.info("[{}] Refund for cause: [{}], rent gas: [{}]", invoke.hashCode(), cause, rentGasValue);
        }
        getResult().refundGas(rentGasValue);
    }

    public void futureRefundGas(long gasValue) {
        if (isLogEnabled) { // #mish: should this be isGasLogEnabled?
            logger.info("Future refund added: [{}]", gasValue); // and gaslogger.info instead ?
        }
        getResult().addFutureRefund(gasValue);
    }

    /*public void futureRentGasRefund(long rentGasValue) {
        if (isRentGasLogEnabled) { // #mish: should this be isGasLogEnabled?
            rentGasLogger.info("Future refund added: [{}]", rentGasValue);
        }
        getResult().addFutureRentGasRefund(rentGasValue);
    }*/

    public void resetFutureRefund() {
        getResult().resetFutureRefund();
    }

    /*public void resetFutureRentGasRefund() {
        getResult().resetFutureRentGasRefund();
    }*/

    public void storageSave(DataWord word1, DataWord word2) {
        storageSave(word1.getData(), word2.getData());
    }

    private void storageSave(byte[] key, byte[] val) {
        // DataWord constructor some times reference the passed byte[] instead
        // of making a copy.
        DataWord keyWord = DataWord.valueOf(key);
        DataWord valWord = DataWord.valueOf(val);

        getStorage().addStorageRow(getOwnerRskAddress(), keyWord, valWord);
    }

    private RskAddress getOwnerRskAddress() {
        if (rskOwnerAddress == null) {
            rskOwnerAddress = new RskAddress(getOwnerAddress());
        }

        return rskOwnerAddress;
    }

    public byte[] getCode() {
        return Arrays.copyOf(ops, ops.length);
    }

    // #mish: why do these getCodeAt methods use invoke.getRepository() and not getStorage()? 
    public Keccak256 getCodeHashAt(RskAddress addr) { return invoke.getRepository().getCodeHash(addr); }

    public Keccak256 getCodeHashAt(DataWord address) { return getCodeHashAt(new RskAddress(address)); }

    public int getCodeLengthAt(RskAddress addr) {
        return invoke.getRepository().getCodeLength(addr);
    }

    public int getCodeLengthAt(DataWord address) {
        return getCodeLengthAt(new RskAddress(address));
    }

    public byte[] getCodeAt(DataWord address) {
        return getCodeAt(new RskAddress(address));
    }

    private byte[] getCodeAt(RskAddress addr) {
        byte[] code = invoke.getRepository().getCode(addr);
        return nullToEmpty(code);
    }

    public DataWord getOwnerAddress() {
        return invoke.getOwnerAddress();
    }

    public DataWord getBlockHash(DataWord dw) {
        long blockIndex = dw.longValueSafe();
        // always returns positive, returns Integer.MAX_VALUE on overflows
        // block number would normally overflow int32 after ~1000 years (at 1 block every 10 seconds)
        // So int32 arithmetic is ok, but we use int64 anyway.
        return getBlockHash(blockIndex);
    }

    public DataWord getBlockHash(long index) {
        long bn = this.getNumber().longValue();
        if ((index <  bn) && (index >= Math.max(0, bn - 256))) {
            return DataWord.valueOf(this.invoke.getBlockStore().getBlockHashByNumber(index, getPrevHash().getData()));
        } else {
            return DataWord.ZERO;
        }
    }

    public DataWord getBalance(DataWord address) {
        Coin balance = getStorage().getBalance(new RskAddress(address));
        return DataWord.valueOf(balance.getBytes());
    }

    // #mish this is no longer "origin", but same as caller or sender (see progInvokeFactoryImpl)
    // was supposed to be the original sender of a TX (never a contract). Deprecated?
    public DataWord getOriginAddress() {
        return invoke.getOriginAddress();
    }

    public DataWord getCallerAddress() {
        return invoke.getCallerAddress();
    }

    public DataWord getGasPrice() {
        return invoke.getMinGasPrice();
    }

    public long getRemainingGas() {
        return invoke.getGas()- getResult().getGasUsed();
    }

    /*public long getRemainingRentGas() {
        return invoke.getRentGas()- getResult().getRentGasUsed();
    }*/

    public DataWord getCallValue() {
        return invoke.getCallValue();
    }

    public DataWord getDataSize() {
        return invoke.getDataSize();
    }

    public DataWord getDataValue(DataWord index) {
        return invoke.getDataValue(index);
    }

    public byte[] getDataCopy(DataWord offset, DataWord length) {
        return invoke.getDataCopy(offset, length);
    }

    public DataWord storageLoad(DataWord key) {
        return getStorage().getStorageValue(getOwnerRskAddress(), key);
    }

    public DataWord getPrevHash() {
        return invoke.getPrevHash();
    }

    public DataWord getCoinbase() {
        return invoke.getCoinbase();
    }

    public DataWord getTimestamp() {
        return invoke.getTimestamp();
    }

    public DataWord getNumber() {
        return invoke.getNumber();
    }

    public DataWord getTransactionIndex() {
        return invoke.getTransactionIndex();
    }

    public DataWord getDifficulty() {
        return invoke.getDifficulty();
    }

    public DataWord getGasLimit() {
        return invoke.getGaslimit();
    }

    // static calls cannot modify state
    public boolean isStaticCall() {
        return invoke.isStaticCall();
    }

    public ProgramResult getResult() {
        return result;
    }

    public void setRuntimeFailure(RuntimeException e) {
        getResult().setException(e);
    }

    public String memoryToString() {
        if (memory.size()>100000) {
            return "<Memory too long to show>";
        } else {
            return memory.toString();
        }
    }

    /** #mish: Called externally, not used here */
    public void fullTrace() {

        if (logger.isTraceEnabled() || listener != null) {

            StringBuilder stackData = new StringBuilder();
            for (int i = 0; i < stack.size(); ++i) {
                stackData.append(" ").append(stack.get(i));
                if (i < stack.size() - 1) {
                    stackData.append("\n");
                }
            }

            if (stackData.length() > 0) {
                stackData.insert(0, "\n");
            }

            RskAddress ownerAddress = new RskAddress(getOwnerAddress());
            StringBuilder storageData = new StringBuilder();
            if (getStorage().isContract(ownerAddress)) {
                Iterator<DataWord> it = getStorage().getStorageKeys(ownerAddress);
                while (it.hasNext()) {
                    DataWord key = it.next();
                    storageData.append(" ").append(key).append(" -> ").
                            append(getStorage().getStorageValue(ownerAddress, key)).append('\n');
                }
                if (storageData.length() > 0) {
                    storageData.insert(0, "\n");
                }
            }

            StringBuilder memoryData = new StringBuilder();
            StringBuilder oneLine = new StringBuilder();
            if (memory.size() > 320) {
                memoryData.append("... Memory Folded.... ")
                        .append("(")
                        .append(memory.size())
                        .append(") bytes");
            }
            else {
                for (int i = 0; i < memory.size(); ++i) {

                    byte value = memory.readByte(i);
                    oneLine.append(ByteUtil.oneByteToHexString(value)).append(" ");

                    if ((i + 1) % 16 == 0) {
                        String tmp = format("[%4s]-[%4s]", Integer.toString(i - 15, 16),
                                Integer.toString(i, 16)).replace(" ", "0");
                        memoryData.append("").append(tmp).append(" ");
                        memoryData.append(oneLine);
                        if (i < memory.size()) {
                            memoryData.append("\n");
                        }
                        oneLine.setLength(0);
                    }
                }
            }
            if (memoryData.length() > 0) {
                memoryData.insert(0, "\n");
            }

            StringBuilder opsString = new StringBuilder();
            for (int i = 0; i < ops.length; ++i) {

                String tmpString = Integer.toString(ops[i] & 0xFF, 16);
                tmpString = tmpString.length() == 1 ? "0" + tmpString : tmpString;

                if (i != pc) {
                    opsString.append(tmpString);
                } else {
                    opsString.append(" >>").append(tmpString).append("");
                }

            }
            if (pc >= ops.length) {
                opsString.append(" >>");
            }
            if (opsString.length() > 0) {
                opsString.insert(0, "\n ");
            }

            logger.trace(" -- OPS --     {}", opsString);
            logger.trace(" -- STACK --   {}", stackData);
            logger.trace(" -- MEMORY --  {}", memoryData);
            logger.trace(" -- STORAGE -- {}\n", storageData);
            logger.trace("\n  Spent Gas: [{}]/[{}]\n  Left Gas:  [{}]\n",
                    getResult().getGasUsed(),
                    invoke.getGas(),
                    getRemainingGas());
            /*logger.trace("\n  Spent Rent Gas: [{}]/[{}]\n  Left Rent Gas:  [{}]\n",
                    getResult().getRentGasUsed(),
                    invoke.getRentGas(),
                    getRemainingRentGas());*/

            StringBuilder globalOutput = new StringBuilder("\n");
            if (stackData.length() > 0) {
                stackData.append("\n");
            }

            if (pc != 0) {
                globalOutput.append("[Op: ").append(OpCode.code(lastOp).name()).append("]\n");
            }

            globalOutput.append(" -- OPS --     ").append(opsString).append("\n");
            globalOutput.append(" -- STACK --   ").append(stackData).append("\n");
            globalOutput.append(" -- MEMORY --  ").append(memoryData).append("\n");
            globalOutput.append(" -- STORAGE -- ").append(storageData).append("\n");

            if (getResult().getHReturn() != null) {
                globalOutput.append("\n  HReturn: ").append(
                        Hex.toHexString(getResult().getHReturn()));
            }

            // sophisticated assumption that msg.data != codedata
            // means we are calling the contract not creating it
            byte[] txData = invoke.getDataCopy(DataWord.ZERO, getDataSize());
            if (!Arrays.equals(txData, ops)) {
                globalOutput.append("\n  msg.data: ").append(Hex.toHexString(txData));
            }
            globalOutput.append("\n\n  Spent Gas: ").append(getResult().getGasUsed());
            globalOutput.append("\n\n  Spent Rent Gas: ").append(getResult().getRentGasUsed());

            if (listener != null) {
                listener.output(globalOutput.toString());
            }
        }
    }

    public void saveOpTrace() {
        if (this.pc < ops.length) {
            trace.addOp(ops[pc], pc, getCallDeep(), getRemainingGas(), this.memory, this.stack, this.storage);
        }
    }

    public void saveOpGasCost(long gasCost) {
        trace.saveGasCost(gasCost);
    }

    public ProgramTrace getTrace() {
        return trace;
    }

    private int processAndSkipCodeHeader(int offset) {
        int ret = offset;
        if (ops.length >= 4) {
            OpCode op = OpCode.code(ops[0]);
            if ((op != null) && op == OpCode.HEADER) {
                // next byte is executable format version
                // header length in bytes
                int exe = ops[1] & 0xff;
                // limit to positive to prevent version 0xff < 0x00
                exeVersion = (byte) Math.min(exe, 127);

                // limit to positive to prevent version 0xff < 0x00
                int script = ops[2] & 0xff;
                scriptVersion = (byte) Math.min(script, 127);
                int extHeaderLen = ops[3] & 0xff;
                ret = offset + 4 + extHeaderLen;
                startAddr = ret;
                pc = ret;
            }
        }
        return ret;
    }

    private void precompile() {
        int i = 0;
        exeVersion = 0;
        scriptVersion = 0;
        startAddr = 0;
        pc = 0;
        i = processAndSkipCodeHeader(i);
        computeJumpDests(i);
    }

    private void computeJumpDests(int start) {
        if (jumpdestSet == null) {
            jumpdestSet = new BitSet(ops.length);
        }

        for (int i = start; i < ops.length; ++i) {
            OpCode op = OpCode.code(ops[i]);

            if (op == null) {
                continue;
            }

            if (op == OpCode.JUMPDEST) {
                jumpdestSet.set(i);
            }

            if (op.asInt() >= OpCode.PUSH1.asInt() && op.asInt() <= OpCode.PUSH32.asInt()) {
                i += op.asInt() - OpCode.PUSH1.asInt() + 1;
            }
        }
    }

    public DataWord getReturnDataBufferSize() {
        return DataWord.valueOf(getReturnDataBufferSizeI());
    }

    private int getReturnDataBufferSizeI() {
        return returnDataBuffer == null ? 0 : returnDataBuffer.length;
    }

    public Optional<byte[]> getReturnDataBufferData(DataWord off, DataWord size) {
        long endPosition = (long) off.intValueSafe() + size.intValueSafe();
        if (endPosition > getReturnDataBufferSizeI()) {
            return Optional.empty();
        }

        if (returnDataBuffer == null) {
            return Optional.of(new byte[0]);
        }

        byte[] copiedData = Arrays.copyOfRange(returnDataBuffer, off.intValueSafe(), Math.toIntExact(endPosition));
        return Optional.of(copiedData);
    }

    public ActivationConfig.ForBlock getActivations() {
        return activations;
    }

    public void addListener(ProgramOutListener listener) {
        this.listener = listener;
    }

    public int verifyJumpDest(DataWord nextPC) {
        // This is painstankly slow
        if (nextPC.occupyMoreThan(4)) {
            throw ExceptionHelper.badJumpDestination(-1);
        }
        int ret = nextPC.intValue(); // could be negative
        if (ret < 0 || ret >= jumpdestSet.size() || !jumpdestSet.get(ret)) {
            throw ExceptionHelper.badJumpDestination(ret);
        }
        return ret;
    }

    public void callToPrecompiledAddress(MessageCall msg, PrecompiledContract contract) {

        if (getCallDeep() == getMaxDepth()) {
            stackPushZero();
            this.refundGas(msg.getGas().longValue(), " call deep limit reach");
            return;
        }

        Repository track = getStorage().startTracking();

        RskAddress senderAddress = getOwnerRskAddress();
        RskAddress codeAddress = new RskAddress(msg.getCodeAddress());
        RskAddress contextAddress = msg.getType().isStateless() ? senderAddress : codeAddress;

        Coin endowment = new Coin(msg.getEndowment().getData());
        Coin senderBalance = track.getBalance(senderAddress);
        if (senderBalance.compareTo(endowment) < 0) {
            stackPushZero();
            this.refundGas(msg.getGas().longValue(), "refund gas from message call");
            return;
        }

        byte[] data = this.memoryChunk(msg.getInDataOffs().intValue(),
                msg.getInDataSize().intValue());

        // Charge for endowment - is not reversible by rollback
        track.transfer(senderAddress, contextAddress, new Coin(msg.getEndowment().getData()));

        // we are assuming that transfer is already creating destination account even if the amount is zero
        if (!track.isContract(codeAddress)) {
            track.setupContract(codeAddress);
        }

        if (byTestingSuite()) {
            // This keeps track of the calls created for a test
            this.getResult().addCallCreate(data,
                    codeAddress.getBytes(),
                    msg.getGas().longValueSafe(),
                    msg.getEndowment().getNoLeadZeroesData());

            stackPushOne();
            return;
        }

        // Special initialization for Bridge, Remasc and NativeContract contracts
        if (contract instanceof Bridge || contract instanceof RemascContract || contract instanceof NativeContract) {
            // CREATE CALL INTERNAL TRANSACTION
            InternalTransaction internalTx = addInternalTx(null, getGasLimit(), senderAddress, contextAddress, endowment, EMPTY_BYTE_ARRAY, "call");

            // Propagate the "local call" nature of the originating transaction down to the callee
            internalTx.setLocalCallTransaction(this.transaction.isLocalCallTransaction());

            Block executionBlock = blockFactory.newBlock(
                    blockFactory.getBlockHeaderBuilder()
                        .setParentHash(getPrevHash().getData())
                        .setCoinbase(new RskAddress(getCoinbase().getLast20Bytes()))
                        .setDifficultyFromBytes(getDifficulty().getData())
                        .setNumber(getNumber().longValue())
                        .setGasLimit(getGasLimit().getData())
                        .setTimestamp(getTimestamp().longValue())
                        .build(),
                    Collections.emptyList(),
                    Collections.emptyList()
            );

            contract.init(internalTx, executionBlock, track, this.invoke.getBlockStore(), null, null);
        }

        long requiredGas = contract.getGasForData(data);
        if (requiredGas > msg.getGas().longValue()) {

            this.refundGas(0, "call pre-compiled"); //matches cpp logic
            this.stackPushZero();
            track.rollback();
        } else {

            this.refundGas(msg.getGas().longValue() - requiredGas, "call pre-compiled");

            byte[] out = contract.execute(data);
            if (getActivations().isActive(ConsensusRule.RSKIP90)) {
                this.returnDataBuffer = out;
            }

            // Avoid saving null returns to memory and limit the memory it can use.
            // If we're behind RSK150 activation, don't care about the null return, just save.
            if (getActivations().isActive(ConsensusRule.RSKIP150) && out != null) {
                this.memorySaveLimited(msg.getOutDataOffs().intValue(), out, msg.getOutDataSize().intValue());
            } else if (!getActivations().isActive(ConsensusRule.RSKIP150)) {
                this.memorySave(msg.getOutDataOffs().intValue(), out);
            }
            this.stackPushOne();
            track.commit();
        }
    }

    private boolean byTestingSuite() {
        return invoke.byTestingSuite();
    }
 
    public interface ProgramOutListener {
        void output(String out);
    }

    @SuppressWarnings("serial")
    public static class OutOfGasException extends RuntimeException {

        public OutOfGasException(String message, Object... args) {
            super(format(message, args));
        }
    }
    
    // #mish to be explicit about exceptions rising from rent gas
    @SuppressWarnings("serial")
    public static class OutOfRentGasException extends RuntimeException {

        public OutOfRentGasException(String message, Object... args) {
            super(format(message, args));
        }
    }

    @SuppressWarnings("serial")
    public static class IllegalOperationException extends RuntimeException {

        public IllegalOperationException(String message, Object... args) {
            super(format(message, args));
        }
    }

    @SuppressWarnings("serial")
    public static class BadJumpDestinationException extends RuntimeException {

        public BadJumpDestinationException(String message, Object... args) {
            super(format(message, args));
        }
    }

    @SuppressWarnings("serial")
    public static class StackTooSmallException extends RuntimeException {

        public StackTooSmallException(String message, Object... args) {
            super(format(message, args));
        }
    }
    public static class StaticCallModificationException extends RuntimeException {
        public StaticCallModificationException() {
            super("Attempt to call a state modifying opcode inside STATICCALL");
        }
    }

    public static class AddressCollisionException extends RuntimeException {
        public AddressCollisionException(String message) {
            super(message);
        }
    }

    public static class ExceptionHelper {

        private ExceptionHelper() { }

        public static StaticCallModificationException modificationException() {
            return new StaticCallModificationException();
        }

        public static OutOfGasException notEnoughOpGas(OpCode op, long opGas, long programGas) {
            return new OutOfGasException("Not enough gas for '%s' operation executing: opGas[%d], programGas[%d];", op, opGas, programGas);
        }

        public static OutOfGasException notEnoughOpGas(OpCode op, DataWord opGas, DataWord programGas) {
            return notEnoughOpGas(op, opGas.longValue(), programGas.longValue());
        }

        public static OutOfGasException notEnoughOpGas(OpCode op, BigInteger opGas, BigInteger programGas) {
            return notEnoughOpGas(op, opGas.longValue(), programGas.longValue());
        }

        public static OutOfGasException notEnoughSpendingGas(String cause, long gasValue, Program program) {
            return new OutOfGasException("Not enough gas for '%s' cause spending: invokeGas[%d], gas[%d], usedGas[%d];",
                    cause, program.invoke.getGas(), gasValue, program.getResult().getGasUsed());
        }

        public static OutOfGasException gasOverflow(BigInteger actualGas, BigInteger gasLimit) {
            return new OutOfGasException("Gas value overflow: actualGas[%d], gasLimit[%d];", actualGas.longValue(), gasLimit.longValue());
        }
        public static OutOfGasException gasOverflow(long actualGas, BigInteger gasLimit) {
            return new OutOfGasException("Gas value overflow: actualGas[%d], gasLimit[%d];", actualGas, gasLimit.longValue());
        }
        
        /*public static OutOfRentGasException notEnoughRentGas(String cause, long rentGasValue, Program program) {
            return new OutOfRentGasException("Not enough rent gas for '%s' cause spending: invokeGas[%d], rentGas[%d], usedRentGas[%d];",
                    cause, program.invoke.getRentGas(), rentGasValue, program.getResult().getRentGasUsed());
        }*/
        
        public static IllegalOperationException invalidOpCode(byte... opCode) {
            return new IllegalOperationException("Invalid operation code: opcode[%s];", Hex.toHexString(opCode, 0, 1));
        }

        public static BadJumpDestinationException badJumpDestination(int pc) {
            return new BadJumpDestinationException("Operation with pc isn't 'JUMPDEST': PC[%d];", pc);
        }

        public static StackTooSmallException tooSmallStack(int expectedSize, int actualSize) {
            return new StackTooSmallException("Expected stack size %d but actual %d;", expectedSize, actualSize);
        }

        public static RuntimeException tooLargeContractSize(int maxSize, int actualSize) {
            return new RuntimeException(format("Maximum contract size allowed %d but actual %d;", maxSize, actualSize));
        }

        public static AddressCollisionException addressCollisionException(RskAddress address) {
            return new AddressCollisionException("Trying to create a contract with existing contract address: 0x" + address.toString());
        }
    }

    @SuppressWarnings("serial")
    public class StackTooLargeException extends RuntimeException {
        public StackTooLargeException(String message) {
            super(message);
        }
    }

    /**
     * used mostly for testing reasons
     */
    public byte[] getMemory() {
        return memory.read(0, memory.size());
    }

    /**
     * used mostly for testing reasons
     */
    public void initMem(byte[] data) {
        this.memory.write(0, data, data.length, false);
    }

    public byte getExeVersion() {
        return exeVersion;
    }
    public byte getScriptVersion() {
        return scriptVersion;
    }
    public int getStartAddr(){
        return startAddr;
    }

    @VisibleForTesting
    public BitSet getJumpdestSet() { return this.jumpdestSet; }
}
