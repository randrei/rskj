package co.rsk.peg.pegininstructions;

import co.rsk.core.RskAddress;
import org.ethereum.util.ByteUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public abstract class PeginInstructionsBase implements PeginInstructions {

    private static final Logger logger = LoggerFactory.getLogger(PeginInstructionsBase.class);
    private final int protocolVersion;
    protected RskAddress rskDestinationAddress;

    protected PeginInstructionsBase(int protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    private RskAddress getRskDestinationAddressFromData(byte[] data) {
        byte[] rskDestinationAddressBytes = Arrays.copyOfRange(data, 2, 22);
        return new RskAddress(rskDestinationAddressBytes);
    }

    protected abstract void validateDataLength(byte[] data) throws PeginInstructionsParseException;

    protected abstract void parseAdditionalData(byte[] data) throws PeginInstructionsParseException;

    public static int extractProtocolVersion(byte[] data) throws PeginInstructionsParseException {
        if (data == null || data.length < 2) {
            String message;

            if (data == null) {
                message = "Provided data is null";
            } else {
                message = String.format("Invalid data given. Expected at least 2 bytes, " +
                    "received %d", data.length);
            }

            logger.debug("[extractProtocolVersion] {}", message);
            throw new PeginInstructionsParseException(message);
        }

        byte[] protocolVersionBytes = Arrays.copyOfRange(data, 0, 2);
        return ByteUtil.byteArrayToInt(protocolVersionBytes);
    }

    @Override
    public RskAddress getRskDestinationAddress() {
        return this.rskDestinationAddress;
    }

    @Override
    public int getProtocolVersion() {
        return this.protocolVersion;
    }

    public void parse(byte[] data) throws PeginInstructionsParseException {
        validateDataLength(data);
        this.rskDestinationAddress = getRskDestinationAddressFromData(data);
        parseAdditionalData(data);
    }
}
