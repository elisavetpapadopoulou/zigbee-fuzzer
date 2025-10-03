package com.github.protocolfuzzing.zigbeefuzzer.symbols;

import java.util.Collections;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.AbstractOutput;

public class OutputZigbee extends AbstractOutput<OutputZigbee, Object> {
    public OutputZigbee(String name) {
        super(name);
        this.messages = Collections.emptyList();
    }

    @Override
    protected OutputZigbee buildOutput(String name) {
        return new OutputZigbee(name);
    }

    @Override
    protected OutputZigbee convertOutput() {
        return this;
    }

}
