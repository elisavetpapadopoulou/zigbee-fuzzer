package io.github.protocolfuzzing.zigbeefuzzer;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSUL;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULAdapter;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.sulwrappers.DynamicPortProvider;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.Mapper;
import io.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
import jep.SharedInterpreter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SulZigbee implements AbstractSUL<InputZigbee, OutputZigbee, ExecutionContextZigbee> {
    private static final Logger LOGGER = LogManager.getLogger();
    protected MapperZigbee dummyMapper;
    protected DynamicPortProvider dynamicPortProvider;
    protected SulServerConfigZigbee config;
    protected CleanupTasks cleanupTasks;
    protected SharedInterpreter interp;

    private final ExecutorService pyExec =
        Executors.newSingleThreadExecutor(r -> new Thread(r, "PyThread"));

    private <T> T onPy(Callable<T> task) {
        try {
            return pyExec.submit(task).get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void onPy(Runnable task) {
        onPy(Executors.callable(task, null));
    }

    public SulZigbee(SULConfig sulConfig, CleanupTasks cleanupTasks) {
        this.dummyMapper = new MapperZigbee();
        this.config = (SulServerConfigZigbee) sulConfig;
        this.cleanupTasks = cleanupTasks;

        final String mapper;
        if (config.getMapper() != null) {
            mapper = "ZigbeeSUL_" + config.getMapper();
        } else {
            mapper = "ZigbeeSUL";
        }

        onPy(() -> {
            interp = new SharedInterpreter();
            interp.exec("import sys; sys.path.insert(0, 'py')");
            interp.exec(String.format("from %s import %s as SUL", mapper, mapper));
            interp.exec(String.format("b = SUL('%s', '%s')",
                    config.getAdapterSerialPort(), config.getTargetMacAddr()));
        });

        cleanupTasks.submit(() -> {
            LOGGER.debug("Closing serial port...");
            try {
                onPy(() -> {
                    if (interp != null) {
                        try {
                            interp.exec("b.close()");
                        } catch (Throwable t) {
                            LOGGER.warn("Python-side close failed", t);
                        } finally {
                            try {
                                interp.close();
                            } catch (Throwable ignore) {
                            }
                            interp = null;
                        }
                    }
                });
            } finally {
                pyExec.shutdownNow();
            }
        });
    }

    @Override
    public void pre() {
        LOGGER.debug("SulZigbee: pre");
        onPy(() -> interp.exec("b.pre()"));
    }

    @Override
    public OutputZigbee step(InputZigbee in) {
        LOGGER.debug("SulZigbee: step");
        return onPy(() -> {
            interp.set("insym", in.getName());
            interp.exec("outsym = b.step(insym)");
            String outputSymbol = (String) interp.getValue("outsym");
            return new OutputZigbee(outputSymbol);
        });
    }

    @Override
    public void post() {
        LOGGER.debug("SulZigbee: post");
        onPy(() -> interp.exec("b.post()"));
    }

    @Override
    public SULConfig getSULConfig() {
        return config;
    }

    @Override
    public CleanupTasks getCleanupTasks() {
        return cleanupTasks;
    }

    @Override
    public void setDynamicPortProvider(DynamicPortProvider dynamicPortProvider) {
        this.dynamicPortProvider = dynamicPortProvider;
    }

    @Override
    public DynamicPortProvider getDynamicPortProvider() {
        return this.dynamicPortProvider;
    }

    @Override
    public Mapper<InputZigbee, OutputZigbee, ExecutionContextZigbee> getMapper() {
        return this.dummyMapper;
    }

    @Override
    public SULAdapter getSULAdapter() {
        return null;
    }
}
