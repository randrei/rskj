package co.rsk.peg.performance;

import co.rsk.bitcoinj.core.*;
import co.rsk.bitcoinj.script.RedeemScriptParser;
import co.rsk.bitcoinj.script.Script;
import co.rsk.bitcoinj.script.ScriptBuilder;
import co.rsk.bitcoinj.store.BlockStoreException;
import co.rsk.bitcoinj.store.BtcBlockStore;
import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import co.rsk.peg.*;
import org.ethereum.config.Constants;
import org.ethereum.config.blockchain.upgrades.ActivationConfigsForTest;
import org.ethereum.core.Repository;
import org.ethereum.crypto.ECKey;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Ignore
public class RegisterFastBridgeBtcTransactionTest extends BridgePerformanceTestCase {
    private BtcTransaction btcTx;
    private int blockWithTxHeight;
    private Keccak256 derivationArgumentsHash;
    private Address userRefundAddress;
    private RskAddress lbcAddress;
    private Address lpBtcAddress;
    private boolean shouldTransferToContract =  true;
    private BtcBlock blockWithTx;
    private PartialMerkleTree pmt;
    private Coin totalAmount;


    @BeforeClass
    public static void setupA() {
        constants = Constants.regtest();
        activationConfig = ActivationConfigsForTest.all();
    }

    @Test
    public void registerFastBridgeBtcTransaction() {
        ExecutionStats stats = new ExecutionStats("registerFastBridgeBtcTransaction");
        registerFastBridgeBtcTransaction_success(1000, stats);
      //  registerFastBridgeBtcTransaction_surpasses_locking_cap(1, stats);
        BridgePerformanceTest.addStats(stats);
    }

    private void registerFastBridgeBtcTransaction_success(int times, ExecutionStats stats) {

        BtcECKey btcECKeyUserRefundAddress = new BtcECKey();
        userRefundAddress = btcECKeyUserRefundAddress.toAddress(networkParameters);

        ECKey ecKey = new ECKey();
        lbcAddress = new RskAddress(ecKey.getAddress());

        BtcECKey btcECKeyLpBtcAddress = new BtcECKey();
        lpBtcAddress = btcECKeyLpBtcAddress.toAddress(networkParameters);

        derivationArgumentsHash  = PegTestUtils.createHash3(1);

        totalAmount = Coin.CENT.multiply(Helper.randomInRange(1, 5));

        BridgeStorageProviderInitializer storageInitializer = generateInitializerForTest(
                1000,
                2000
        );

        executeAndAverage(
                "registerFastBridgeBtcTransaction_success",
                times,
                getABIEncoder(),
                storageInitializer,
                Helper.getTxBuilderWithInternalTransaction(lbcAddress),
                Helper.getRandomHeightProvider(10),
                stats,
                (environment, executionResult) -> {
                    long totalAmount = new BigInteger(executionResult).longValueExact();
                    Assert.assertTrue(totalAmount > 0);
                }
        );
    }

    private void registerFastBridgeBtcTransaction_surpasses_locking_cap(int times, ExecutionStats stats) {

        BtcECKey btcECKeyUserRefundAddress = new BtcECKey();
        userRefundAddress = btcECKeyUserRefundAddress.toAddress(networkParameters);

        ECKey ecKey = new ECKey();
        lbcAddress = new RskAddress(ecKey.getAddress());

        BtcECKey btcECKeyLpBtcAddress = new BtcECKey();
        lpBtcAddress = btcECKeyLpBtcAddress.toAddress(networkParameters);

        derivationArgumentsHash  = PegTestUtils.createHash3(1);

        totalAmount = Coin.CENT.multiply(Helper.randomInRange(10000000, 50000000));
        int surpassesLockinCapError = -200;

        BridgeStorageProviderInitializer storageInitializer = generateInitializerForTest(
                1000,
                2000
        );

        executeAndAverage(
                "registerFastBridgeBtcTransaction_success",
                times,
                getABIEncoder(),
                storageInitializer,
                Helper.getTxBuilderWithInternalTransaction(lbcAddress),
                Helper.getRandomHeightProvider(10),
                stats,
                (environment, executionResult) -> {
                    long errorResult = new BigInteger(executionResult).longValueExact();
                    Assert.assertEquals(surpassesLockinCapError, errorResult);
                }
        );
    }

    private ABIEncoder getABIEncoder() {

        return (int executionIndex) ->
                BridgeMethods.REGISTER_FAST_BRIDGE_BTC_TRANSACTION.getFunction().encode(new Object[]{
                        btcTx.bitcoinSerialize(),
                        blockWithTxHeight,
                        pmt.bitcoinSerialize(),
                        derivationArgumentsHash.getBytes(),
                        userRefundAddress.getHash160(),
                        lbcAddress.toHexString(),
                        lpBtcAddress.getHash160(),
                        shouldTransferToContract
                });
    }

    private BridgeStorageProviderInitializer generateInitializerForTest(int minBtcBlocks, int maxBtcBlocks) {
        return (BridgeStorageProvider provider, Repository repository, int executionIndex, BtcBlockStore blockStore) -> {
                BtcBlockStoreWithCache.Factory btcBlockStoreFactory = new RepositoryBtcBlockStoreWithCache.Factory(bridgeConstants.getBtcParams());
                Repository thisRepository = repository.startTracking();
                BtcBlockStore btcBlockStore = btcBlockStoreFactory.newInstance(thisRepository);
                Context btcContext = new Context(networkParameters);
                BtcBlockChain btcBlockChain;
                try {
                    btcBlockChain = new BtcBlockChain(btcContext, btcBlockStore);
                } catch (BlockStoreException e) {
                    throw new RuntimeException("Error initializing btc blockchain for tests");
                }

                int blocksToGenerate = Helper.randomInRange(minBtcBlocks, maxBtcBlocks);
                BtcBlock lastBlock = Helper.generateAndAddBlocks(btcBlockChain, blocksToGenerate);

                Script fastBridgeRedeemScript = RedeemScriptParser.createMultiSigFastBridgeRedeemScript(
                        bridgeConstants.getGenesisFederation().getRedeemScript(),
                        Sha256Hash.wrap(
                                BridgeSupport.getFastBridgeDerivationHash(
                                        derivationArgumentsHash,
                                        userRefundAddress,
                                        lpBtcAddress,
                                        lbcAddress
                                ).getBytes()
                        )
                );

                Script fastBridgeP2SH = ScriptBuilder.createP2SHOutputScript(fastBridgeRedeemScript);
                Address fastBridgeFederationAddress = Address.fromP2SHScript(bridgeConstants.getBtcParams(), fastBridgeP2SH);

                btcTx = createBtcTransactionWithOutputToAddress(totalAmount, fastBridgeFederationAddress);

                pmt = PartialMerkleTree.buildFromLeaves(networkParameters, new byte[]{(byte) 0xff}, Arrays.asList(btcTx.getHash()));
                List<Sha256Hash> hashes = new ArrayList<>();
                Sha256Hash merkleRoot = pmt.getTxnHashAndMerkleRoot(hashes);

                blockWithTx = Helper.generateBtcBlock(lastBlock, Arrays.asList(btcTx), merkleRoot);
                btcBlockChain.add(blockWithTx);
                blockWithTxHeight = btcBlockChain.getBestChainHeight();

                Helper.generateAndAddBlocks(btcBlockChain, 10);
                thisRepository.commit();
                thisRepository.commit();
        };
    }

    private BtcTransaction createBtcTransactionWithOutputToAddress(Coin amount, Address btcAddress) {
        BtcTransaction tx = new BtcTransaction(bridgeConstants.getBtcParams());
        tx.addOutput(amount, btcAddress);
        BtcECKey srcKey = new BtcECKey();
        tx.addInput(PegTestUtils.createHash(1),
                0, ScriptBuilder.createInputScript(null, srcKey));
        return tx;
    }
}
