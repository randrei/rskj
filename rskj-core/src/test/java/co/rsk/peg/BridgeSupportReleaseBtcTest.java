package co.rsk.peg;

import co.rsk.bitcoinj.core.*;
import co.rsk.config.BridgeConstants;
import co.rsk.config.BridgeRegTestConstants;
import co.rsk.core.RskAddress;
import co.rsk.db.MutableTrieCache;
import co.rsk.db.MutableTrieImpl;
import co.rsk.peg.btcLockSender.BtcLockSenderProvider;
import co.rsk.peg.utils.BridgeEventLogger;
import co.rsk.peg.utils.BridgeEventLoggerImpl;
import co.rsk.peg.utils.RejectedPegoutReason;
import co.rsk.trie.Trie;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.config.Constants;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ActivationConfigsForTest;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;
import org.ethereum.core.Block;
import org.ethereum.core.CallTransaction;
import org.ethereum.core.Repository;
import org.ethereum.core.Transaction;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.HashUtil;
import org.ethereum.db.MutableRepository;
import org.ethereum.vm.DataWord;
import org.ethereum.vm.LogInfo;
import org.ethereum.vm.PrecompiledContracts;
import org.ethereum.vm.program.InternalTransaction;
import org.ethereum.vm.program.Program;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class BridgeSupportReleaseBtcTest {

    private static final String TO_ADDRESS = "0000000000000000000000000000000000000006";
    private static final BigInteger DUST_AMOUNT = new BigInteger("1");
    private static final BigInteger NONCE = new BigInteger("0");
    private static final BigInteger GAS_PRICE = new BigInteger("100");
    private static final BigInteger GAS_LIMIT = new BigInteger("1000");
    private static final String DATA = "80af2871";
    private static final ECKey SENDER = new ECKey();

    private BridgeConstants bridgeConstants;
    private ActivationConfig.ForBlock activationsBeforeForks;
    private ActivationConfig.ForBlock activationMock = mock(ActivationConfig.ForBlock.class);
    private Federation activeFederation;
    private Repository repository;
    private BridgeEventLogger eventLogger;
    private UTXO utxo;
    private BridgeStorageProvider provider;
    private BridgeSupport bridgeSupport;
    private Transaction releaseTx;

    @Before
    public void setUpOnEachTest() throws IOException {
        bridgeConstants = BridgeRegTestConstants.getInstance();
        activationsBeforeForks = ActivationConfigsForTest.genesis().forBlock(0);
        activeFederation = getFederation();
        repository = spy(createRepository());
        eventLogger = mock(BridgeEventLogger.class);
        utxo = buildUTXO();
        provider = initProvider(repository, activationMock);
        bridgeSupport = spy(initBridgeSupport(eventLogger, activationMock));
        releaseTx = buildReleaseRskTx();
    }

    @Test
    public void noLogEvents_before_rskip_146_185() throws IOException {
        provider = initProvider(repository, activationsBeforeForks);
        bridgeSupport = initBridgeSupport(eventLogger, activationsBeforeForks);

        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());
        verify(eventLogger, never()).logReleaseBtcRequested(any(byte[].class), any(BtcTransaction.class), any(Coin.class));
        verify(eventLogger, never()).logReleaseBtcRequestReceived(any(), any(), any());
        verify(eventLogger, never()).logReleaseBtcRequestRejected(any(), any(), any());
    }

    @Test
    public void eventLogger_logReleaseBtcRequested_after_rskip_146() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);

        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());
        verify(eventLogger, times(1)).logReleaseBtcRequested(any(byte[].class), any(BtcTransaction.class), any(Coin.class));
        verify(eventLogger, never()).logReleaseBtcRequestReceived(any(), any(), any());
        verify(eventLogger, never()).logReleaseBtcRequestRejected(any(), any(), any());
    }

    @Test
    public void eventLogger_logReleaseBtcRequested_after_rskip_146_185() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(true);

        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());
        verify(eventLogger, times(1)).logReleaseBtcRequested(any(byte[].class), any(BtcTransaction.class), any(Coin.class));
        verify(eventLogger, times(1)).logReleaseBtcRequestReceived(any(), any(), any());
        verify(eventLogger, times(0)).logReleaseBtcRequestRejected(any(), any(), any());
    }

    @Test
    public void eventLogger_logReleaseBtcRequested_release_before_activation_and_updateCollections_after_activation() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(false);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(false);

        bridgeSupport.releaseBtc(releaseTx);

        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(true);

        bridgeSupport = initBridgeSupport(eventLogger, activationMock);

        Transaction rskTx = buildUpdateTx();
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());
        verify(eventLogger, never()).logReleaseBtcRequested(any(byte[].class), any(BtcTransaction.class), any(Coin.class));
        verify(eventLogger, never()).logReleaseBtcRequestReceived(any(), any(), any());
        verify(eventLogger, never()).logReleaseBtcRequestRejected(any(), any(), any());
    }

    @Test
    public void handmade_release_before_rskip_146_185() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(false);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(false);

        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        rskTx.sign(new ECKey().getPrivKeyBytes());
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());
        assertEquals(1, provider.getReleaseTransactionSet().getEntries().size());
        assertEquals(0, provider.getReleaseRequestQueue().getEntries().size());

        verify(eventLogger, never()).logReleaseBtcRequested(any(byte[].class), any(BtcTransaction.class), any(Coin.class));
        verify(eventLogger, never()).logReleaseBtcRequestReceived(any(), any(), any());
        verify(eventLogger, never()).logReleaseBtcRequestRejected(any(), any(), any());
    }

    @Test
    public void handmade_release_after_rskip_146() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(false);

        List<LogInfo> logInfo = new ArrayList<>();
        BridgeEventLoggerImpl eventLogger = new BridgeEventLoggerImpl(bridgeConstants, activationMock, logInfo);
        bridgeSupport = initBridgeSupport(eventLogger, activationMock);

        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        rskTx.sign(new ECKey().getPrivKeyBytes());
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());
        assertEquals(1, provider.getReleaseTransactionSet().getEntries().size());
        assertEquals(0, provider.getReleaseRequestQueue().getEntries().size());
        ReleaseTransactionSet.Entry entry = (ReleaseTransactionSet.Entry) provider.getReleaseTransactionSet().getEntries().toArray()[0];
        assertEvent(logInfo, 1, BridgeEvents.RELEASE_REQUESTED.getEvent(), new Object[]{releaseTx.getHash().getBytes(), entry.getTransaction().getHash().getBytes()}, new Object[]{Coin.COIN.value});
    }

    @Test
    public void handmade_release_after_rskip_146_185() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(true);

        List<LogInfo> logInfo = new ArrayList<>();
        BridgeEventLoggerImpl eventLogger = new BridgeEventLoggerImpl(bridgeConstants, activationMock, logInfo);
        bridgeSupport = initBridgeSupport(eventLogger, activationMock);

        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        rskTx.sign(SENDER.getPrivKeyBytes());
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());

        assertEquals(1, provider.getReleaseTransactionSet().getEntries().size());
        assertEquals(0, provider.getReleaseRequestQueue().getEntries().size());
        ReleaseTransactionSet.Entry entry = (ReleaseTransactionSet.Entry) provider.getReleaseTransactionSet().getEntries().toArray()[0];

        assertEquals(3, logInfo.size());

        assertEvent(logInfo, 0, BridgeEvents.RELEASE_REQUEST_RECEIVED.getEvent(), new Object[]{rskTx.getSender().toHexString()}, new Object[]{getBtcDestinationAddress(releaseTx), Coin.COIN.value});
        assertEvent(logInfo, 1, BridgeEvents.UPDATE_COLLECTIONS.getEvent(), new Object[]{}, new Object[]{rskTx.getSender().toHexString()});
        assertEvent(logInfo, 2, BridgeEvents.RELEASE_REQUESTED.getEvent(), new Object[]{releaseTx.getHash().getBytes(), entry.getTransaction().getHash().getBytes()}, new Object[]{Coin.COIN.value});
    }

    @Test
    public void handmade_release_after_rskip_146_rejected() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(false);


        List<LogInfo> logInfo = new ArrayList<>();
        BridgeEventLoggerImpl eventLogger = new BridgeEventLoggerImpl(bridgeConstants, activationMock, logInfo);
        bridgeSupport = initBridgeSupport(eventLogger, activationMock);

        releaseTx = buildReleaseRskTx(Coin.ZERO);
        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        rskTx.sign(SENDER.getPrivKeyBytes());
        bridgeSupport.updateCollections(rskTx);

        verify(repository, never()).transfer(any(), any(), any());

        assertEquals(0, provider.getReleaseTransactionSet().getEntries().size());
        assertEquals(0, provider.getReleaseRequestQueue().getEntries().size());

        assertEquals(1, logInfo.size());

        assertEvent(logInfo, 0, BridgeEvents.UPDATE_COLLECTIONS.getEvent(), new Object[]{}, new Object[]{rskTx.getSender().toHexString()});
    }

    @Test
    public void handmade_release_after_rskip_146_185_rejected_lowAmount() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(true);


        List<LogInfo> logInfo = new ArrayList<>();
        BridgeEventLoggerImpl eventLogger = new BridgeEventLoggerImpl(bridgeConstants, activationMock, logInfo);
        bridgeSupport = initBridgeSupport(eventLogger, activationMock);

        releaseTx = buildReleaseRskTx(Coin.ZERO);
        bridgeSupport.releaseBtc(releaseTx);

        Transaction rskTx = buildUpdateTx();
        rskTx.sign(SENDER.getPrivKeyBytes());
        bridgeSupport.updateCollections(rskTx);

        verify(repository, times(1)).transfer(
                argThat((a) -> a.equals(PrecompiledContracts.BRIDGE_ADDR)),
                argThat((a) -> a.equals(new RskAddress(SENDER.getAddress()))),
                argThat((a) -> a.equals(co.rsk.core.Coin.fromBitcoin(Coin.ZERO)))
        );

        assertEquals(0, provider.getReleaseTransactionSet().getEntries().size());
        assertEquals(0, provider.getReleaseRequestQueue().getEntries().size());

        assertEquals(2, logInfo.size());

        assertEvent(logInfo, 0, BridgeEvents.RELEASE_REQUEST_REJECTED.getEvent(), new Object[]{rskTx.getSender().toHexString()}, new Object[]{Coin.ZERO.value, RejectedPegoutReason.LOW_AMOUNT.getValue()});
        assertEvent(logInfo, 1, BridgeEvents.UPDATE_COLLECTIONS.getEvent(), new Object[]{}, new Object[]{rskTx.getSender().toHexString()});
    }


    @Test
    public void handmade_release_after_rskip_146_185_rejected_contractCaller() throws IOException {
        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(true);


        List<LogInfo> logInfo = new ArrayList<>();
        BridgeEventLoggerImpl eventLogger = new BridgeEventLoggerImpl(bridgeConstants, activationMock, logInfo);
        bridgeSupport = initBridgeSupport(eventLogger, activationMock);

        releaseTx = buildReleaseRskTx_Contract(Coin.COIN);
        bridgeSupport.releaseBtc(releaseTx);

        // Create Contract transaction
        Transaction rskTx = buildUpdateTx();
        rskTx.sign(SENDER.getPrivKeyBytes());
        bridgeSupport.updateCollections(rskTx);

        verify(repository, times(1)).transfer(
                argThat((a) -> a.equals(PrecompiledContracts.BRIDGE_ADDR)),
                argThat((a) -> a.equals(new RskAddress(SENDER.getAddress()))),
                argThat((a) -> a.equals(co.rsk.core.Coin.fromBitcoin(Coin.COIN)))
        );

        assertEquals(0, provider.getReleaseTransactionSet().getEntries().size());
        assertEquals(0, provider.getReleaseRequestQueue().getEntries().size());

        assertEquals(2, logInfo.size());

        assertEvent(logInfo, 0, BridgeEvents.RELEASE_REQUEST_REJECTED.getEvent(), new Object[]{rskTx.getSender().toHexString()}, new Object[]{Coin.COIN.value, RejectedPegoutReason.CALLER_CONTRACT.getValue()});
        assertEvent(logInfo, 1, BridgeEvents.UPDATE_COLLECTIONS.getEvent(), new Object[]{}, new Object[]{rskTx.getSender().toHexString()});
    }

    @Test
    public void handmade_release_after_rskip_146_rejected_contractCaller() throws IOException {

        when(activationMock.isActive(ConsensusRule.RSKIP146)).thenReturn(true);
        when(activationMock.isActive(ConsensusRule.RSKIP185)).thenReturn(false);

        List<LogInfo> logInfo = new ArrayList<>();
        BridgeEventLoggerImpl eventLogger = new BridgeEventLoggerImpl(bridgeConstants, activationMock, logInfo);
        bridgeSupport = initBridgeSupport(eventLogger, activationMock);

        releaseTx = buildReleaseRskTx_Contract(Coin.COIN);
        try {
            bridgeSupport.releaseBtc(releaseTx);
            fail();
        }catch (Program.OutOfGasException e) {
            assertTrue(e.getMessage().contains("Contract calling releaseBTC"));
        }
    }

    /**********************************
     *  -------     UTILS     ------- *
     *********************************/

    private byte[] getBtcDestinationAddress(Transaction rskTx) {
        NetworkParameters btcParams = bridgeConstants.getBtcParams();
        return BridgeUtils.recoverBtcAddressFromEthTransaction(rskTx, btcParams).getHash160();
    }

    private static void assertEvent(List<LogInfo> logs, int index, CallTransaction.Function event, Object[] topics, Object[] params) {
        final LogInfo log = logs.get(index);
        assertEquals(LogInfo.byteArrayToList(event.encodeEventTopics(topics)), log.getTopics());
        assertArrayEquals(event.encodeEventData(params), log.getData());
    }

    private UTXO buildUTXO() {
        return new UTXO(Sha256Hash.wrap(HashUtil.randomHash()), 0, Coin.COIN.multiply(2), 1, false, activeFederation.getP2SHScript());
    }

    private Transaction buildReleaseRskTx() {
        return buildReleaseRskTx(Coin.COIN);
    }

    private Transaction buildReleaseRskTx(Coin coin) {
        Transaction releaseTx = Transaction
                .builder()
                .nonce(NONCE)
                .gasPrice(GAS_PRICE)
                .gasLimit(GAS_LIMIT)
                .destination(PrecompiledContracts.BRIDGE_ADDR.toHexString())
                .data(Hex.decode(DATA))
                .chainId(Constants.REGTEST_CHAIN_ID)
                .value(co.rsk.core.Coin.fromBitcoin(coin).asBigInteger())
                .build();
        releaseTx.sign(SENDER.getPrivKeyBytes());
        return releaseTx;
    }

    private Transaction buildReleaseRskTx_Contract(Coin coin) {
        Transaction releaseTx = Transaction
                .builder()
                .nonce(NONCE)
                .gasPrice(GAS_PRICE)
                .gasLimit(GAS_LIMIT)
                .destination(PrecompiledContracts.BRIDGE_ADDR.toHexString())
                .data(Hex.decode(DATA))
                .chainId(Constants.REGTEST_CHAIN_ID)
                .value(co.rsk.core.Coin.fromBitcoin(Coin.COIN).asBigInteger())
                .build();
        releaseTx.sign(SENDER.getPrivKeyBytes());
        return new InternalTransaction(releaseTx.getHash().getBytes(), 400, 0, NONCE.toByteArray(),
                DataWord.valueOf(GAS_PRICE.intValue()), DataWord.valueOf(GAS_LIMIT.intValue()), SENDER.getAddress(),
                PrecompiledContracts.BRIDGE_ADDR.getBytes(), co.rsk.core.Coin.fromBitcoin(Coin.COIN).getBytes(),
                Hex.decode(DATA), "");
    }

    private Transaction buildUpdateTx() {
        return Transaction
                .builder()
                .nonce(NONCE)
                .gasPrice(GAS_PRICE)
                .gasLimit(GAS_LIMIT)
                .destination(Hex.decode(TO_ADDRESS))
                .data(Hex.decode(DATA))
                .chainId(Constants.REGTEST_CHAIN_ID)
                .value(DUST_AMOUNT)
                .build();
    }

    private BridgeSupport initBridgeSupport(BridgeEventLogger eventLogger, ActivationConfig.ForBlock activationMock) {
        return getBridgeSupport(
                bridgeConstants, provider, repository, eventLogger, mock(Block.class), null, activationMock);
    }

    private BridgeStorageProvider initProvider(Repository repository, ActivationConfig.ForBlock activationMock) throws IOException {
        BridgeStorageProvider provider = new BridgeStorageProvider(repository, PrecompiledContracts.BRIDGE_ADDR, bridgeConstants, activationMock);
        provider.getNewFederationBtcUTXOs().add(utxo);
        provider.setNewFederation(activeFederation);
        return provider;
    }

    private static Repository createRepository() {
        return new MutableRepository(new MutableTrieCache(new MutableTrieImpl(null, new Trie())));
    }

    private BridgeSupport getBridgeSupport(BridgeConstants constants, BridgeStorageProvider provider, Repository track,
                                           BridgeEventLogger eventLogger, Block executionBlock,
                                           BtcBlockStoreWithCache.Factory blockStoreFactory,
                                           ActivationConfig.ForBlock activations) {
        return getBridgeSupport(
                constants,
                provider,
                track,
                eventLogger,
                new BtcLockSenderProvider(),
                executionBlock,
                blockStoreFactory,
                activations
        );
    }


    private BridgeSupport getBridgeSupport(BridgeConstants constants, BridgeStorageProvider provider, Repository track,
                                           BridgeEventLogger eventLogger, BtcLockSenderProvider btcLockSenderProvider,
                                           Block executionBlock, BtcBlockStoreWithCache.Factory blockStoreFactory,
                                           ActivationConfig.ForBlock activations) {
        if (btcLockSenderProvider == null) {
            btcLockSenderProvider = mock(BtcLockSenderProvider.class);
        }
        if (blockStoreFactory == null) {
            blockStoreFactory = mock(BtcBlockStoreWithCache.Factory.class);
        }
        return new BridgeSupport(
                constants,
                provider,
                eventLogger,
                btcLockSenderProvider,
                track,
                executionBlock,
                new Context(constants.getBtcParams()),
                new FederationSupport(constants, provider, executionBlock),
                blockStoreFactory,
                activations
        );
    }

    private static Federation getFederation() {
        return new Federation(
                FederationTestUtils.getFederationMembers(3),
                Instant.ofEpochMilli(1000),
                0L,
                NetworkParameters.fromID(NetworkParameters.ID_REGTEST)
        );
    }

}
