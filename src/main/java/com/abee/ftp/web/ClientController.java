package com.abee.ftp.web;

import com.abee.ftp.client.MyFtpClient;
import com.abee.ftp.client.secure.Authenticator;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;

/**
 * @author xincong yao
 */
@RestController
@RequestMapping("client")
public class ClientController {

    private MyFtpClient client;

    @RequestMapping
    public ModelAndView index() {
        return new ModelAndView("client.html");
    }

    @RequestMapping("connect")
    public String connect(String ip, Integer port) {
        client = new MyFtpClient();

        try {
            client.connect(ip, port);
        } catch (IOException e) {
            return e.getMessage();
        }

        return "Connected to server " + ip + ":" + port;
    }

    @RequestMapping("authenticate")
    public String authenticate(String ip, int port) {
        Authenticator authenticator = new Authenticator();
        authenticator.connect(ip, port);

        String result = "ERROR.";
        if (authenticator.authenticate()) {
            result = "OK";
        }

        return result;
    }

    @RequestMapping("upload")
    public String upload(String local, String remote, boolean withSecurity) {
        if (client == null) {
            return "You should connect to server first.";
        }

        try {
            client.upload(local, remote, withSecurity);
        } catch (IOException | ClassNotFoundException e) {
            return "Unknown Error.";
        }

        return "Upload done.";
    }

    @RequestMapping("download")
    public String download(String local, String remote, boolean withSecurity) {
        if (client == null) {
            return "You should connect to server first.";
        }

        try {
            client.download(remote, local, withSecurity);
        } catch (IOException | ClassNotFoundException e) {
            return "Unknown Error.";
        }

        return "Download done.";
    }
}
