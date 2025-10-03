package com.github.protocolfuzzing.zigbeefuzzer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSul;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulAdapter;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.sulwrappers.DynamicPortProvider;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.Mapper;
import com.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;

import jep.SharedInterpreter;

import java.util.concurrent.*;

public class SulZigbee implements AbstractSul<InputZigbee, OutputZigbee, ExecutionContextZigbee> {
    private static final Logger LOGGER = LogManager.getLogger();
    protected MapperZigbee dummyMapper;
    protected DynamicPortProvider dynamicPortProvider;
    protected SulServerConfigZigbee config;
    protected CleanupTasks cleanupTasks;
    protected SharedInterpreter interp;

    private final ExecutorService pyExec =
        Executors.newSingleThreadExecutor(r -> new Thread(r, "PyThread"));

    private <T> T onPy(Callable<T> task) {
        try { return pyExec.submit(task).get(); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    private void onPy(Runnable task) { onPy(Executors.callable(task, null)); }

    public SulZigbee(SulConfig sulConfig, CleanupTasks cleanupTasks) {
        this.dummyMapper = new MapperZigbee();
        this.config = (SulServerConfigZigbee) sulConfig;
        this.cleanupTasks = cleanupTasks;

        final String mapper;
        if (config.getMapper() != null) mapper = "ZigbeeSUL_" + config.getMapper();
        else mapper = "ZigbeeSUL";

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
                        try { interp.exec("b.close()"); }
                        catch (Throwable t) { LOGGER.warn("Python-side close failed", t); }
                        finally {
                            try { interp.close(); } catch (Throwable ignore) {}
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

    @Override public SulConfig getSulConfig() { return config; }
    @Override public CleanupTasks getCleanupTasks() { return cleanupTasks; }
    @Override public void setDynamicPortProvider(DynamicPortProvider dynamicPortProvider) { this.dynamicPortProvider = dynamicPortProvider; }
    @Override public DynamicPortProvider getDynamicPortProvider() { return this.dynamicPortProvider; }
    @Override public Mapper<InputZigbee, OutputZigbee, ExecutionContextZigbee> getMapper() { return this.dummyMapper; }
    @Override public SulAdapter getSulAdapter() { return null; }
}

