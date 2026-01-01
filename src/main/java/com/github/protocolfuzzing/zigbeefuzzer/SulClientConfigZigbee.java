package com.github.protocolfuzzing.zigbeefuzzer;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulAdapterConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulClientConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfig;

public class SulClientConfigZigbee extends SulClientConfigStandard {
    private Integer port = null;
    private Long clientWait = 50L;

    public SulClientConfigZigbee(MapperConfig mapperConfig, SulAdapterConfig sulAdapterConfig) {
        super(mapperConfig, sulAdapterConfig);
    }

    @Override
    public Integer getPort() {
        return port;
    }

    @Override
    public void setPort(Integer port) {
        this.port = port;
    }

    @Override
    public Long getClientWait() {
        return clientWait;
    }

    @Override
    public SulConfig cloneWithThreadId(int threadId){
        SulAdapterConfig newAdapterConfig = (SulAdapterConfig) this.sulAdapterConfig;
        MapperConfig newMapperConfig = (MapperConfig) this.mapperConfig;
        return new SulClientConfigZigbee(newMapperConfig, newAdapterConfig);
    }

}
