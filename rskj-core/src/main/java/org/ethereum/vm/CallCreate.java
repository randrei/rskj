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


package org.ethereum.vm;

/**
 * @author Roman Mandeleil
 * @since 03.07.2014
 */
public class CallCreate {

    final byte[] data;
    final byte[] destination;
    final long gasLimit;
    //final long rentGasLimit; // #mish storage rent
    final byte[] value;

    /* to be deleted to maintain a single gas field
    public CallCreate(byte[] data, byte[] destination, long gasLimit, byte[] value, long rentGasLimit) {
        this.data = data;
        this.destination = destination;
        this.gasLimit = gasLimit;
        this.rentGasLimit = rentGasLimit;
        this.value = value;
    }
    */
    
    public CallCreate(byte[] data, byte[] destination, long gasLimit, byte[] value) {
        this.data = data;
        this.destination = destination;
        this.gasLimit = gasLimit;
        //this.rentGasLimit = gasLimit; // #mish as per RSKIP113, if rentgaslimit is not specified, set it equal to gaslimit
        this.value = value;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getDestination() {
        return destination;
    }

    public long getGasLimit() {
        return gasLimit;
    }

    /*
    public long getRentGasLimit() {
        return rentGasLimit;
    }
    */

    public byte[] getValue() {
        return value;
    }
}
