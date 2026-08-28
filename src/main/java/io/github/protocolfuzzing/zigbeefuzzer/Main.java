package io.github.protocolfuzzing.zigbeefuzzer;

import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.statistics.MealyMachineWrapper;
import io.github.protocolfuzzing.protocolstatefuzzer.entrypoints.CommandLineParser;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import io.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;

public class Main {
    public static void main(String[] args) {
        // Multibuilder implements all necessary builders
        MultiBuilder mb = new MultiBuilder();

        // single parentLogger, if Main resides in the outermost package
        String[] parentLoggers = {Main.class.getPackageName()};

        CommandLineParser<MealyMachineWrapper<InputZigbee, OutputZigbee>> commandLineParser =
            new CommandLineParser<MealyMachineWrapper<InputZigbee, OutputZigbee>>(mb, mb, mb, mb, mb, mb);
        commandLineParser.setExternalParentLoggers(parentLoggers);

        commandLineParser.process(args, true);
    }
}
