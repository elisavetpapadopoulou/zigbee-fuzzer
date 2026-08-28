package io.github.protocolfuzzing.zigbeefuzzer;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.Mapper;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfig;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.OutputBuilderZigbee;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.OutputCheckerZigbee;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;

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
