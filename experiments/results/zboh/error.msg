Non-determinism detected
full input:
MAC_BEACON_REQUEST MAC_ASSOCIATION_REQUEST MAC_DATA_REQUEST MAC_DATA_REQUEST NWK_REJOIN_REQUEST
full new output:
MAC_BEACON EMPTYRESPONSE MAC_ASSOCIATION_RESPONSE APS_CMD_TRANSPORT_NWK_KEY EMPTYRESPONSE
old output:
MAC_BEACON EMPTYRESPONSE MAC_ASSOCIATION_RESPONSE APS_CMD_TRANSPORT_NWK_KEY 
preceding input:
MAC_BEACON_REQUEST MAC_ASSOCIATION_REQUEST MAC_DATA_REQUEST MAC_DATA_REQUEST NWK_REJOIN_REQUEST MAC_ORPHAN_NOTIFY MAC_DATA_REQUEST
com.github.protocolfuzzing.protocolstatefuzzer.components.learner.oracles.NonDeterminismException: Non-determinism detected
full input:
MAC_BEACON_REQUEST MAC_ASSOCIATION_REQUEST MAC_DATA_REQUEST MAC_DATA_REQUEST NWK_REJOIN_REQUEST
full new output:
MAC_BEACON EMPTYRESPONSE MAC_ASSOCIATION_RESPONSE APS_CMD_TRANSPORT_NWK_KEY EMPTYRESPONSE
old output:
MAC_BEACON EMPTYRESPONSE MAC_ASSOCIATION_RESPONSE APS_CMD_TRANSPORT_NWK_KEY 
preceding input:
MAC_BEACON_REQUEST MAC_ASSOCIATION_REQUEST MAC_DATA_REQUEST MAC_DATA_REQUEST NWK_REJOIN_REQUEST MAC_ORPHAN_NOTIFY MAC_DATA_REQUEST
	at com.github.protocolfuzzing.protocolstatefuzzer.components.learner.oracles.MultipleRunsSULOracle.getProbabilisticOutput(MultipleRunsSULOracle.java:188)
	at com.github.protocolfuzzing.protocolstatefuzzer.components.learner.oracles.MultipleRunsSULOracle.getMultipleRunOutput(MultipleRunsSULOracle.java:119)
	at com.github.protocolfuzzing.protocolstatefuzzer.components.learner.oracles.NonDeterminismRetryingSULOracle.getCheckedOutput(NonDeterminismRetryingSULOracle.java:83)
	at com.github.protocolfuzzing.protocolstatefuzzer.components.learner.oracles.NonDeterminismRetryingSULOracle.processQuery(NonDeterminismRetryingSULOracle.java:61)
	at de.learnlib.oracle.MembershipOracle.answerQuery(MembershipOracle.java:46)
	at de.learnlib.oracle.MembershipOracle.answerQuery(MembershipOracle.java:40)
	at com.github.protocolfuzzing.protocolstatefuzzer.components.learner.oracles.CachingSULOracle.processQueries(CachingSULOracle.java:75)
	at de.learnlib.oracle.MembershipOracle.processQuery(MembershipOracle.java:62)
	at com.github.protocolfuzzing.protocolstatefuzzer.components.learner.oracles.LoggingSULOracle.processQueries(LoggingSULOracle.java:71)
	at de.learnlib.datastructure.discriminationtree.model.AbstractDiscriminationTree.sift(AbstractDiscriminationTree.java:117)
	at de.learnlib.algorithm.ttt.base.BaseTTTDiscriminationTree.sift(BaseTTTDiscriminationTree.java:71)
	at de.learnlib.algorithm.ttt.base.AbstractTTTLearner.updateDTTargets(AbstractTTTLearner.java:916)
	at de.learnlib.algorithm.ttt.base.AbstractTTTLearner.closeTransitions(AbstractTTTLearner.java:825)
	at de.learnlib.algorithm.ttt.base.AbstractTTTLearner.closeTransitions(AbstractTTTLearner.java:789)
	at de.learnlib.algorithm.ttt.base.AbstractTTTLearner.refineHypothesisSingle(AbstractTTTLearner.java:242)
	at de.learnlib.algorithm.ttt.mealy.TTTLearnerMealy.refineHypothesisSingle(TTTLearnerMealy.java:92)
	at de.learnlib.algorithm.ttt.base.AbstractTTTLearner.refineHypothesis(AbstractTTTLearner.java:173)
	at com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerStandard.inferStateMachine(StateFuzzerStandard.java:165)
	at com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerStandard.startFuzzing(StateFuzzerStandard.java:84)
	at com.github.protocolfuzzing.protocolstatefuzzer.entrypoints.CommandLineParser.executeCommand(CommandLineParser.java:355)
	at com.github.protocolfuzzing.protocolstatefuzzer.entrypoints.CommandLineParser.parseAndExecuteCommand(CommandLineParser.java:226)
	at com.github.protocolfuzzing.protocolstatefuzzer.entrypoints.CommandLineParser.parse(CommandLineParser.java:168)
	at com.github.protocolfuzzing.protocolstatefuzzer.entrypoints.CommandLineParser.parse(CommandLineParser.java:199)
	at com.github.protocolfuzzing.zigbeefuzzer.Main.main(Main.java:19)
