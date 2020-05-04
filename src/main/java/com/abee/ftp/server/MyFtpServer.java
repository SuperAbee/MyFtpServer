package com.abee.ftp.server;

import com.abee.ftp.common.listener.CommandListener;
import com.abee.ftp.config.ServerContext;
import com.abee.ftp.secure.AuthorityCenter;

/**
 * @author xincong yao
 */
public class MyFtpServer {

    /**
     * todo: It could be a List, not only one single listener.
     */
    private CommandListener commandListener;

    private AuthorityCenter authorityCenter;

    public void start() {
        if (commandListener != null) {
            commandListener.start();
            authorityCenter.start();
        }
    }

    public boolean setRoot(String root) {
        return ServerContext.setRoot(root);
    }

    public void setCommandListener(CommandListener listener) {
        commandListener = listener;
    }

    public void setAuthorityCenter(AuthorityCenter c) {
        this.authorityCenter = c;
    }
}
