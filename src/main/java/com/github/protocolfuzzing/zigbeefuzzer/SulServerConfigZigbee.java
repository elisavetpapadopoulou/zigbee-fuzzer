package com.github.protocolfuzzing.zigbeefuzzer;

import java.io.PrintWriter;

import com.beust.jcommander.Parameter;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulServerConfig;

public class SulServerConfigZigbee implements SulServerConfig {
    
    @Parameter(names = "-port", description = "TCP port for the Zigbee driver server")
    protected Integer port = 6000;

    @Parameter(names = "-adapter", required = true,
               description = "The serial port of the test adapter")
    protected String serialPort = null;

    @Parameter(names = "-mapper",
               description = "Allows selecting a device specific mapper")
    protected String mapper = null;

    @Parameter(names = "-connect", required = true,
               description = "The Zigbee MAC address of the target device")
    protected String targetMacAddr = null;
    

    public String getAdapterSerialPort() {
        return serialPort;
    }

    public String getMapper() {
        return mapper;
    }

    public String getTargetMacAddr() {
        return targetMacAddr;
    }
    

    @Override
    public String getHost() {
        return targetMacAddr;
    }

    @Override
    public void setHost(String host) {
        this.targetMacAddr = host;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }


    @Override
    public void printRunDescriptionSelf(PrintWriter printWriter) {
        printWriter.println("SulServerConfigZigbee Parameters");
        printWriter.println("Zigbee Adapter: " + getAdapterSerialPort());
        printWriter.println("Mapper: " + getMapper());
        printWriter.println("Target addr: " + getTargetMacAddr());
    }

    @Override
    public SulServerConfigZigbee cloneWithThreadId(int threadId) {
        SulServerConfigZigbee cloned = new SulServerConfigZigbee();
        cloned.serialPort = this.serialPort;
        cloned.mapper = this.mapper;
        cloned.targetMacAddr = this.targetMacAddr;
        if (this.port != null) {
            cloned.port = this.port + threadId;
        }
        return cloned;
    }
}
