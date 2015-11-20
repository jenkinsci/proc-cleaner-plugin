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
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.logging.Logger;

/**
 * Author: psrna
 * Date: 8/2/13
 */
public class PsBasedUnixProcessTree extends PsBasedProcessTree {

    @Override
    public PsBasedProcessTree createProcessTreeFor(String user) throws InterruptedException, IOException {
        String[] cmd = {"ps","-u",user,"-o","pid,ppid,args"};
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        if (proc.waitFor() != 0) {
            LOGGER.warning("'ps' command invocation " + cmd + " failed!");
            LOGGER.fine("Received output from 'ps' command invocation follows:");

            if(getLog() != null) {
                getLog().println("WARNING: 'ps' command invocation " + cmd + " failed!");
                getLog().println("DEBUG: Received output from 'ps' command invocation follows:");
            }

            String line;
            while ((line = reader.readLine()) != null) {
                LOGGER.fine(line);
                if(getLog() != null)
                    getLog().println("DEBUG: '" + line + "'");
            }
        }

        PsBasedProcessTree ptree = new PsBasedUnixProcessTree();
        String line = reader.readLine(); // first line should be "PID  PPID COMMAND" - skip it
        if(!line.matches("^\\s*PID\\s*PPID\\s*(COMMAND|ARGS)\\s*$")) {
            LOGGER.fine("Unrecognized first output line from 'ps' command invocation! Was: '" + line + "'");
            if(getLog() != null) {
            getLog().println("DEBUG: Unrecognized first output line from 'ps' command invocation! Was: '"
                    + line + "'");
            }
            return null;
        }

        while((line = reader.readLine()) != null)
            ptree.addProcess(line);
        ptree.setLog(getLog());
        return ptree;
    }

    private static final Logger LOGGER = Logger.getLogger(PsBasedUnixProcessTree.class.getName());

}
