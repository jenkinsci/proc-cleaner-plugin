/*
 * The MIT License
 *
 * Copyright (c) 2014 Red Hat, Inc.
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

import static org.junit.Assert.assertTrue;
import static org.jenkinsci.plugins.proccleaner.Util.getLogAsString;
import hudson.model.Build;
import hudson.model.FreeStyleProject;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.MyJenkinsRule;

public class GroovyScriptCleanerTest {

    @Rule public MyJenkinsRule j = new MyJenkinsRule();

    @Test public void runGroovy() throws Exception {
        FreeStyleProject job = j.createFreeStyleProject();
        Util.setPreProcCleaner(job, new GroovyScriptCleaner("println 'precleaner'; return 'precleaned!'"));
        Util.setPostProcCleaner(job, new GroovyScriptCleaner("println 'postcleaner'; return 'postcleaned!'"));

        Build<?,?> build = job.scheduleBuild2(0).get();
        String log = getLogAsString(build);

        assertTrue(log.contains("precleaner"));
        assertTrue(log.contains("Result: precleaned!"));
        assertTrue(log.contains("postcleaner"));
        assertTrue(log.contains("Result: postcleaned!"));
    }

    @Test public void failGroovy() throws Exception {
        FreeStyleProject job = j.createFreeStyleProject();
        Util.setPreProcCleaner(job, new GroovyScriptCleaner("throw new NullPointerException('Failed groovy script');"));

        Build<?,?> build = job.scheduleBuild2(0).get();
        String log = getLogAsString(build);

        assertTrue(log.contains("java.lang.NullPointerException: Failed groovy script"));
    }
}
