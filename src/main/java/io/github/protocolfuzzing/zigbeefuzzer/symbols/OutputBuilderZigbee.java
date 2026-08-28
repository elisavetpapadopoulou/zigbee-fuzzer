package io.github.protocolfuzzing.zigbeefuzzer.symbols;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputBuilder;

public class OutputBuilderZigbee extends OutputBuilder<OutputZigbee> {

    @Override
    public OutputZigbee buildOutputExact(String name) {
        return new OutputZigbee(name);
    }
}
