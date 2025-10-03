package com.github.protocolfuzzing.zigbeefuzzer;

import com.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputBuilderZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputCheckerZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.Mapper;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfig;

public class MapperZigbee implements Mapper<InputZigbee, OutputZigbee, ExecutionContextZigbee> {
    protected OutputBuilder<OutputZigbee> outputBuilder = new OutputBuilderZigbee();
    protected OutputChecker<OutputZigbee> outputChecker = new OutputCheckerZigbee();

    @Override
    public OutputZigbee execute(InputZigbee input, ExecutionContextZigbee context) {
        throw new UnsupportedOperationException("Unimplemented method 'execute'");
    }

    @Override
    public MapperConfig getMapperConfig() {
        return null;
    }

    @Override
    public OutputBuilder<OutputZigbee> getOutputBuilder() {
        return outputBuilder;
    }

    @Override
    public OutputChecker<OutputZigbee> getOutputChecker() {
        return outputChecker;
    }
    
}
