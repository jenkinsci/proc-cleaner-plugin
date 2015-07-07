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
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Author: pjanouse
 * Date: 2015/07/03
 */
public class PsBasedHPUXProcessTree extends PsBasedProcessTree {

    @Override
    public PsBasedProcessTree createProcessTreeFor(String user) throws InterruptedException, IOException {
        String[] cmd = {"ps","-u",user, "-f"};
        BufferedReader reader;
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        proc.waitFor();
        PsBasedProcessTree ptree = new PsBasedHPUXProcessTree();
        String line = reader.readLine(); // first line should be "UID PID PPID C STIME TTY TIME COMMAND" - skip it
        if (!line.matches("^\\s*UID\\s*PID\\s*PPID\\s*C\\s*STIME\\s*TTY\\s*TIME\\s*COMMAND\\s*$")) {
            return null;
        }
        boolean unsupported_ps = false;
        while ((line = reader.readLine()) != null) {
            String[] ps = line.trim().split(" +", 8);
            if (ps.length < 8)
                return null;
            ptree.addProcess(ps[1] + ' ' + ps[2] + ' ' + ps[7]);
        }
        return ptree;
    }

}
