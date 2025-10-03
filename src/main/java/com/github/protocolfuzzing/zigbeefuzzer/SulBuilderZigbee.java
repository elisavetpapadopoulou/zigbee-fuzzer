package com.github.protocolfuzzing.zigbeefuzzer;

import com.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSul;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulWrapper;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulWrapperStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;

public class SulBuilderZigbee implements SulBuilder<InputZigbee, OutputZigbee, ExecutionContextZigbee> {
    @Override
    public AbstractSul<InputZigbee, OutputZigbee, ExecutionContextZigbee> buildSul(SulConfig sulConfig, CleanupTasks cleanupTasks) {
        return new SulZigbee(sulConfig, cleanupTasks);
    }

    @Override
    public SulWrapper<InputZigbee, OutputZigbee, ExecutionContextZigbee> buildWrapper() {
        return new SulWrapperStandard<InputZigbee, OutputZigbee, ExecutionContextZigbee>();
    }
}
