package com.github.protocolfuzzing.zigbeefuzzer.symbols;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;

 public class OutputCheckerZigbee implements OutputChecker<OutputZigbee> {

    @Override
    public boolean hasInitialClientMessage(OutputZigbee output) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasInitialClientMessage'");
    }

    @Override
    public boolean isTimeout(OutputZigbee output) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'isTimeout'");
    }

    @Override
    public boolean isUnknown(OutputZigbee output) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'isUnknown'");
    }

    @Override
    public boolean isSocketClosed(OutputZigbee output) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'isSocketClosed'");
    }

    @Override
    public boolean isDisabled(OutputZigbee output) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'isDisabled'");
    }

}
