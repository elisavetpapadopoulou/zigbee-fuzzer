package io.github.protocolfuzzing.zigbeefuzzer;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSUL;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULWrapper;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULWrapperStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;

public class SulBuilderZigbee implements SULBuilder<InputZigbee, OutputZigbee, ExecutionContextZigbee> {
    @Override
    public AbstractSUL<InputZigbee, OutputZigbee, ExecutionContextZigbee> buildSUL(
        SULConfig sulConfig, CleanupTasks cleanupTasks
    ) {
        return new SulZigbee(sulConfig, cleanupTasks);
    }

    @Override
    public SULWrapper<InputZigbee, OutputZigbee, ExecutionContextZigbee> buildWrapper() {
        return new SULWrapperStandard<InputZigbee, OutputZigbee, ExecutionContextZigbee>();
    }
}
