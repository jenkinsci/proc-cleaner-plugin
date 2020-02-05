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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Author: psrna
 * Date: 8/2/13
 */
public class PsBasedWinProcessTree extends PsBasedProcessTree {

    @Override
    public PsBasedProcessTree createProcessTreeFor(String user) throws InterruptedException, IOException {

        List<Integer> upList = WMICProcess.getUserProcesses(user);

        for(int p : upList){
            try {
                WMICProcess wmicp = new WMICProcess(p);
                getProcessList().add(
                        PsProcessFactory.createPsProcess(wmicp.getPid(), wmicp.getPpid(), wmicp.getArgs(), this));
            } catch (WMICProcess.WMICProcessException e) {
                //no instance for pid, don't add
            }
        }
        if (!isSystemProcessesFilterOff()) {
            LOGGER.fine("Filter system processes");
            if (getLog() != null)
                getLog().println("DEBUG: 'Filter system processes'");

            List<PsProcess> toRemoveProcesses = new ArrayList<PsProcess>();
            for (PsProcess ps: getProcessList()) {
                if (blacklisted(ps)) {
                    if (getLog() != null)
                        getLog().println("DEBUG: 'Filtered out: " + ps + "'");
                    toRemoveProcesses.add(ps);
                }
            }
            getProcessList().removeAll(toRemoveProcesses);
        } // systemProcessesFilterOff is On

        return this;
    }

    // On MS Windows filter system stuff
    private boolean blacklisted(PsProcess p){
        // Filtered stuff should be placed here
        if (p.getArgs().contains("sshd")) {
            return true;
        }
        if (p.getArgs().contains("bash")) {
            return true;
        }
        if (p.getArgs().contains("Explorer")) {
            return true;
        }

        return false;
    }

    private static final Logger LOGGER = Logger.getLogger(PsBasedWinProcessTree.class.getName());
}
