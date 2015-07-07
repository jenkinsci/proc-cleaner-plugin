/*
 * The MIT License
 *
 * Copyright (c) 2015 Red Hat, Inc.
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
import java.util.logging.Logger;

/**
 * Author: pjanouse
 * Date: 2015/07/07
 */
public class PsProcessHPUX extends PsProcess{

    public PsProcessHPUX(int pid, int ppid, String args, PsBasedProcessTree ptree) {
        super(pid, ppid, args, ptree);
    }

    @Override
    public void kill(int signum) {
        // jna doesn't support HP-UX yet
        //LIBC.kill(super.getPid(), signum);
        try {
            String[] cmd = {"kill", "-" + signum, ((Integer) getPid()).toString()};
            BufferedReader reader;
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            proc.waitFor();
        } catch(Exception e) {
            LOGGER.warning("Unexpected exception occurred during killing process with PID: " + getPid() + " [" + e + "]");
        }
    }

    private static final Logger LOGGER = Logger.getLogger(PsBasedHPUXProcessTree.class.getName());

}
