package com.abee.ftp.common.state;

import java.io.Serializable;

/**
 * FTP Server response body, including response code and arguments(optional).
 *
 * @author xincong yao
 */
public class ResponseBody implements Serializable {

    private ResponseCode code;

    private String arg;

    /**
     * only needed when code 227 comes.
     */
    private String passiveIpAddress;
    private int passivePort;

    public ResponseBody(ResponseCode code) {
        this.code = code;
    }

    public ResponseBody(ResponseCode code, String arg) {
        this.code = code;
        this.arg = arg;
    }

    public ResponseBody(ResponseCode code, String arg, String passiveIpAddress, int passivePort) {
        this.code = code;
        this.arg = arg;
        this.passiveIpAddress = passiveIpAddress;
        this.passivePort = passivePort;
    }

    public ResponseBody() {
    }

    @Override
    public String toString() {
        return "ResponseBody{" +
                "code=" + code +
                ", arg='" + arg + '\'' +
                ", passiveIpAddress='" + passiveIpAddress + '\'' +
                ", passivePort='" + passivePort + '\'' +
                '}';
    }

    public ResponseCode getCode() {
        return code;
    }

    public void setCode(ResponseCode code) {
        this.code = code;
    }

    public String getArg() {
        return arg;
    }

    public void setArg(String arg) {
        this.arg = arg;
    }

    public String getPassiveIpAddress() {
        return passiveIpAddress;
    }

    public void setPassiveIpAddress(String passiveIpAddress) {
        this.passiveIpAddress = passiveIpAddress;
    }

    public int getPassivePort() {
        return passivePort;
    }

    public void setPassivePort(int passivePort) {
        this.passivePort = passivePort;
    }
}
