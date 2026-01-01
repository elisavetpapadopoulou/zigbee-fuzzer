package com.github.protocolfuzzing.zigbeefuzzer;

import com.github.protocolfuzzing.zigbeefuzzer.symbols.AlphabetPojoXmlZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.AlphabetBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.AlphabetBuilderStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.xml.AlphabetSerializerXml;
import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.config.LearnerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.statistics.MealyMachineWrapper;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulWrapper;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulWrapperStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulAdapterConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulClientConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzer;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerComposerStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerClientConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerClientConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerConfigBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerEnabler;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerServerConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerServerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.TestRunner;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.TestRunnerBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.TestRunnerStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.config.TestRunnerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.config.TestRunnerEnabler;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.TimingProbe;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.TimingProbeBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.TimingProbeStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.config.TimingProbeConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.config.TimingProbeEnabler;

public class MultiBuilder implements
    StateFuzzerConfigBuilder,
    StateFuzzerBuilder<MealyMachineWrapper<InputZigbee, OutputZigbee>>,
    TestRunnerBuilder,
    TimingProbeBuilder {

    protected AlphabetBuilder<InputZigbee> alphabetBuilder = new AlphabetBuilderStandard<InputZigbee>(
        new AlphabetSerializerXml<InputZigbee, AlphabetPojoXmlZigbee>(InputZigbee.class, AlphabetPojoXmlZigbee.class)
    );

    protected SulBuilder<InputZigbee, OutputZigbee, ExecutionContextZigbee> sulBuilder = new SulBuilderZigbee();
    protected SulWrapper<InputZigbee, OutputZigbee, ExecutionContextZigbee> sulWrapper = new SulWrapperStandard<InputZigbee, OutputZigbee, ExecutionContextZigbee>();

    @Override
    public StateFuzzerClientConfig buildClientConfig() {
        return new StateFuzzerClientConfigStandard(
            new LearnerConfigStandard(),
            new SulClientConfigZigbee(
                new MapperConfigStandard(),
                new SulAdapterConfigStandard()
            ),
            new TestRunnerConfigStandard(),
            new TimingProbeConfigStandard()
        );
    }

    @Override
    public StateFuzzerServerConfig buildServerConfig() {
        return new StateFuzzerServerConfigStandard(
            new LearnerConfigStandard(),
            new SulServerConfigZigbee(),
            new TestRunnerConfigStandard(),
            new TimingProbeConfigStandard()
        );
    }

    @Override
    public StateFuzzer<MealyMachineWrapper<InputZigbee, OutputZigbee>> build(StateFuzzerEnabler stateFuzzerEnabler) {
        return new StateFuzzerStandard<InputZigbee, OutputZigbee>(
            new StateFuzzerComposerStandard<InputZigbee, OutputZigbee, ExecutionContextZigbee>(stateFuzzerEnabler, alphabetBuilder, sulBuilder).initialize()
        );
    }

    @Override
    public TestRunner build(TestRunnerEnabler testRunnerEnabler) {
        return new TestRunnerStandard<InputZigbee, OutputZigbee, Object, ExecutionContextZigbee>(testRunnerEnabler, alphabetBuilder, sulBuilder).initialize();
    }

    @Override
    public TimingProbe build(TimingProbeEnabler timingProbeEnabler) {
        return new TimingProbeStandard<InputZigbee, OutputZigbee, Object, ExecutionContextZigbee>(timingProbeEnabler, alphabetBuilder, sulBuilder).initialize();
    }
}
