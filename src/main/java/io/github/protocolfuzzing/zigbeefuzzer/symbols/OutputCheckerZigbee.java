package io.github.protocolfuzzing.zigbeefuzzer.symbols;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;

public class OutputCheckerZigbee implements OutputChecker<OutputZigbee> {

    @Override
    public boolean hasInitialClientMessage(OutputZigbee output) {
        throw new UnsupportedOperationException("Unimplemented method 'hasInitialClientMessage'");
    }

    @Override
    public boolean isTimeout(OutputZigbee output) {
        throw new UnsupportedOperationException("Unimplemented method 'isTimeout'");
    }

    @Override
    public boolean isUnknown(OutputZigbee output) {
        throw new UnsupportedOperationException("Unimplemented method 'isUnknown'");
    }

    @Override
    public boolean isSocketClosed(OutputZigbee output) {
        throw new UnsupportedOperationException("Unimplemented method 'isSocketClosed'");
    }

    @Override
    public boolean isDisabled(OutputZigbee output) {
        throw new UnsupportedOperationException("Unimplemented method 'isDisabled'");
    }
}
