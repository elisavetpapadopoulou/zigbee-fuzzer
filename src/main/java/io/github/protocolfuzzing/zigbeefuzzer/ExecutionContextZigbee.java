package io.github.protocolfuzzing.zigbeefuzzer;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;

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
