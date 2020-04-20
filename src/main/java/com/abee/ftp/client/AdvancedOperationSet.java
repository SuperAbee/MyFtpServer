package com.abee.ftp.client;

import com.abee.ftp.common.state.ResponseBody;
import com.abee.ftp.common.state.ResponseCode;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.*;
import java.util.Map;
import java.util.Objects;

/**
 * @author xincong yao
 */
public class AdvancedOperationSet extends BasicOperationSet {

    public AdvancedOperationSet(ObjectOutputStream out, ObjectInputStream in) {
        super(out, in);
    }

    @Override
    public boolean uploads(File file) throws IOException, ClassNotFoundException {
        if (file.isDirectory()) {
            for (File f: Objects.requireNonNull(file.listFiles())) {
                if (f.isDirectory()) {
                    mkd(f.getName());
                    String pwd = pwd().getArg();
                    cwd(pwd + "/" + f.getName());
                    uploads(f);
                    cwd(pwd);
                } else {
                    String localMd5 = DigestUtils.md5Hex(new FileInputStream(f));

                    String remoteMd5 = md5(f.getName()).getArg();

                    if (!localMd5.equals(remoteMd5)) {
                        /**
                         * Get a passive port from server
                         */
                        ResponseBody response = pasv();
                        /**
                         * Preparation before real data transfer.
                         */
                        stor(f.getName());
                        /**
                         * Transfer data.
                         */
                        upload(f, response.getPassivePort());
                    }
                }
            }
        } else {
            String localMd5 = DigestUtils.md5Hex(new FileInputStream(file));

            String remoteMd5 = md5(file.getName()).getArg();

            if (!localMd5.equals(remoteMd5)) {
                ResponseBody response = pasv();
                stor(file.getName());
                upload(file, response.getPassivePort());
            }
        }

        return true;
    }

    @Override
    public boolean downloads(File file, String remote) throws IOException, ClassNotFoundException {
        /**
         * if change working directory operation success
         */
        if (cwd(remote).getCode().equals(ResponseCode._250)) {
            Map<String, Boolean> files = list();

            for (String key: files.keySet()) {
                /**
                 * if (isDirectory) ...
                 */
                if (files.get(key)) {
                    File subDirectory = new File(file.getPath() + "/" + key);
                    subDirectory.mkdir();
                    downloads(subDirectory, remote + "/" + key);
                    cwd(remote);
                } else {
                    File f = new File(file.getPath() + "/" + key);

                    String localMd5 = "";
                    if (f.exists()) {
                        localMd5 = DigestUtils.md5Hex(new FileInputStream(f));
                    }

                    String remoteMd5 = md5(key).getArg();

                    if (!localMd5.equals(remoteMd5)) {
                        /**
                         * Get a passive port from server
                         */
                        ResponseBody response = pasv();

                        retr(key);

                        download(f, response.getPassivePort());
                    }
                }
            }
        } else {
            int tag = remote.lastIndexOf("/");

            cwd(remote.substring(0, tag));

            File f = new File(file.getPath() + "/" + remote.substring(tag));

            String localMd5 = "";
            if (file.exists()) {
                localMd5 = DigestUtils.md5Hex(new FileInputStream(f));
            }

            String remoteMd5 = md5(remote.substring(tag)).getArg();

            if (!localMd5.equals(remoteMd5)) {
                ResponseBody response = pasv();

                retr(remote.substring(tag));

                download(f, response.getPassivePort());
            }
        }


        return true;
    }

}
