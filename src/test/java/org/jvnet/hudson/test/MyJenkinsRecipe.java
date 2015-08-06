package org.jvnet.hudson.test;

import junit.framework.TestCase;
import org.jvnet.hudson.test.recipes.Recipe;

import java.io.File;
import java.lang.annotation.Annotation;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;


/**
 * Meta-annotation for recipe annotations, which controls
 * the test environment set up.
 * 
 * This is JUnit4 version of {@link Recipe}.
 *
 * @author Kohsuke Kawaguchi
 * @since 1.436
 */
@Retention(RUNTIME)
@Documented
@Target(ANNOTATION_TYPE)
public @interface MyJenkinsRecipe {
    /**
     * Specifies the class that sets up the test environment.
     *
     * <p>
     * When a recipe annotation is placed on a test method,
     */
    Class<? extends Runner> value();

    /**
     * The code that implements the recipe semantics.
     *
     * @param <T>
     *      The recipe annotation associated with this runner.
     */
    abstract class Runner<T extends Annotation> {
        /**
         * Called during {@link TestCase#setUp()} to prepare the test environment.
         */
        public void setup(MyJenkinsRule jenkinsRule, T recipe) throws Exception {}

        /**
         * Called right before {@link jenkins.model.Jenkins#Jenkins(File, javax.servlet.ServletContext)} is invoked
         * to decorate the hudson home directory.
         */
        public void decorateHome(MyJenkinsRule jenkinsRule, File home) throws Exception {}

        /**
         * Called during {@link TestCase#tearDown()} to shut down the test environment.
         */
        public void tearDown(MyJenkinsRule jenkinsRule, T recipe) throws Exception {}
    }
}
