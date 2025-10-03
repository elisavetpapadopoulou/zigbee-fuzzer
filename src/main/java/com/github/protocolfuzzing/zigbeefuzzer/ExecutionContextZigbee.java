package com.github.protocolfuzzing.zigbeefuzzer;

import com.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;

public class ExecutionContextZigbee implements ExecutionContext<InputZigbee, OutputZigbee, Object> {
    public ExecutionContextZigbee() {}

    @Override
    public Object getState() {
        return null;
    }

    @Override
    public void disableExecution() {}

    @Override
    public void enableExecution() {}

    @Override
    public boolean isExecutionEnabled() {
        return true;
    }

    @Override
    public void setInput(InputZigbee input) {}

    @Override
    public void setOutput(OutputZigbee output) {}
}
