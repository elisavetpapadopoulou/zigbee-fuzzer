package io.github.protocolfuzzing.zigbeefuzzer.symbols;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.AbstractInputXml;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;
import io.github.protocolfuzzing.zigbeefuzzer.ExecutionContextZigbee;

public class InputZigbee extends AbstractInputXml<OutputZigbee, Object, ExecutionContextZigbee> {

    public InputZigbee() {
        super();
    }

    public InputZigbee(String name) {
        super(name);
    }

    @Override
    public void preSendUpdate(ExecutionContextZigbee context) {}

    @Override
    public void postSendUpdate(ExecutionContextZigbee context) {}

    @Override
    public void postReceiveUpdate(
        OutputZigbee output, OutputChecker<OutputZigbee> outputChecker, ExecutionContextZigbee context
    ) {}

    @Override
    public Object generateProtocolMessage(ExecutionContextZigbee context) {
        throw new UnsupportedOperationException("Unimplemented method 'generateProtocolMessage'");
    }
}
