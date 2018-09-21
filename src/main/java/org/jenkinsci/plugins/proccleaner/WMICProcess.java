/*
 * The MIT License
 *
 * Copyright (c) 2013 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.proccleaner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Author: psrna
 * Date: 8/6/13
 */
public class WMICProcess {

    private static final Logger LOGGER = Logger.getLogger(WMICProcess.class.getName());

    private int pid;
    private int ppid;
    private String args;

    public WMICProcess(int pid) throws WMICProcessException{
        this.pid = pid;
        this.ppid = callForPpid(pid);
        this.args = callForArgs(pid);
    }

    private static int callForPpid(int pid) throws WMICProcessException{

        int ppid = -1;
        String cmd = "cmd.exe /c \"WMIC PROCESS where (processid=" + pid + ") get parentprocessid \"";

//        LOGGER.info("command: '" + cmd + "'");
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(cmd);
            process.getOutputStream().close();
            BufferedReader stdin = new BufferedReader((new InputStreamReader(process.getInputStream())));
            String s = stdin.readLine(); //skip first line - it's parentprocessid label
            StringBuffer sb = new StringBuffer();
            while((s = stdin.readLine()) != null){
                sb.append(s+"\n");
                if(!s.isEmpty()){
                    ppid = Integer.valueOf(s.trim());
                }
            }
//            LOGGER.info("Output: \n" + sb.toString());
            stdin.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if(ppid == -1)
            throw new WMICProcessException("no instance for pid:" + pid);
        return ppid;
    }

    private static String callForArgs(int pid) {

        StringBuilder args = new StringBuilder();
        String cmd = "cmd.exe /c \"WMIC PROCESS where (processid=" + pid + ") get caption,commandline \"";

//        LOGGER.info("command: '" + cmd + "'");
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(cmd);
            process.getOutputStream().close();
            BufferedReader stdin = new BufferedReader((new InputStreamReader(process.getInputStream())));
            String s = stdin.readLine(); //skip first line - it's caption and commandline label
            StringBuffer sb = new StringBuffer();
            while((s = stdin.readLine()) != null){
                 sb.append(s+"\n");
                 args.append(s);
            }
//            LOGGER.info("Output: \n" + sb.toString());
            stdin.close();
        }catch (Exception e){
            e.printStackTrace();
        }
        return args.toString();
    }

    protected static List<Integer> getUserProcesses(String user){
        //regex for pid
        Pattern PID_PATTERN = Pattern.compile("(.+Handle=\")(\\d+)(\".+)");
        Pattern RETVAL_PATTERN = Pattern.compile("(\\s*ReturnValue = )(\\d+)(;\\s*)");
        Pattern USER_PATTERN = Pattern.compile("(\\s*User = \")(\\w+)(\";\\s*)");

        Properties p = System.getProperties();
        StringBuffer sb = new StringBuffer();
        for (String n : p.stringPropertyNames()) {
            sb.append("\t'"+n+"': '"+p.getProperty(n)+"'\n");
        }
        LOGGER.info("System properties:\n" + sb.toString());

        sb = new StringBuffer();
        for (String s : System.getenv().keySet()) {
            sb.append("\t'"+s+"': '"+System.getenv(s)+"'\n");
        }
        LOGGER.info("Environment properties:\n" + sb.toString());

        String osName = System.getProperty( "os.name" ).toLowerCase();
        String className = null;
        String methodName = "getUsername";
        if( osName.contains( "windows" ) ){
            className = "com.sun.security.auth.module.NTSystem";
            methodName = "getName";
        }
        else if( osName.contains( "linux" ) ){
            className = "com.sun.security.auth.module.UnixSystem";
        }
        try {
            if (className != null) {
                Class<?> c = Class.forName(className);
                Method method = c.getDeclaredMethod(methodName);
                Object o = c.newInstance();
                LOGGER.info("Logged user: '" + method.invoke(o) + "'");
            }
        } catch (Throwable e) {
            LOGGER.log(Level.INFO, "Unexpected exception during call " + className + "." + methodName + "()", e);
        }

        ArrayList<Integer> uplist = new ArrayList<Integer>();
        String cmd = "cmd.exe /c \"WMIC PROCESS where (name like \"%exe%\") call getowner\"";

        LOGGER.info("command: '" + cmd + "'");
        LOGGER.info("user: '" + user + "'");
        try {
            // Run Windows command
            Process process = Runtime.getRuntime().exec(cmd);


            // Get input stream
            process.getOutputStream().close();
            BufferedReader stdin = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Read and parse command standard output
            String s;
            sb = new StringBuffer();
            while ((s = stdin.readLine()) != null) {
                sb.append(s+"\n");
                //search for pid line
                Matcher mpid = PID_PATTERN.matcher(s);
                if(mpid.matches()){
                    int pid = Integer.valueOf(mpid.group(2));
                    while((s = stdin.readLine()) != null){
                        sb.append(s+"\n");
                        //search for ReturnValue line
                        if(!s.isEmpty()){
                            Matcher mret = RETVAL_PATTERN.matcher(s);
                            if(mret.matches()){
                                int retval = Integer.valueOf(mret.group(2));
                                if(retval == 0){
                                    //call getowner successfull completion
                                    while((s = stdin.readLine()) != null){
                                        sb.append(s+"\n");
                                        LOGGER.info("PID: " + pid + ", PPID: " + callForPpid(pid) + " - " + callForArgs(pid));
                                        //search for user line
                                        Matcher muser = USER_PATTERN.matcher(s);
                                        if(muser.matches() && user.equals(muser.group(2))){
                                            //success, add PID to the list
                                            uplist.add(pid);
                                        }
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            LOGGER.info("Output: \n" + sb.toString());


        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
        return uplist;
    }

    public int getPpid() {
        return ppid;
    }

    public String getArgs() {
        return args;
    }

    public int getPid() {
        return pid;
    }

    public static class WMICProcessException extends Exception {
        
        private static final long serialVersionUID = 4810696271189726206L;

        public WMICProcessException(String message) {
            super(message);
        }
    }
}
