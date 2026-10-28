import React from 'react';
import { Satellite, Radio, ShieldCheck, Activity, Globe } from 'lucide-react';
import { SatelliteMeshTelemetry } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface SatelliteMeshViewProps {
  telemetry: SatelliteMeshTelemetry | null;
  loading: boolean;
}

export default function SatelliteMeshView({
  telemetry,
  loading
}: SatelliteMeshViewProps) {
  const nodes = telemetry?.activeNodes || [
    {
      id: 'SAT-LEO-01',
      name: 'Quantum-Relay-Alpha',
      constellation: 'QUANTUM-RELAY-1' as const,
      altitudeKm: 550.2,
      orbitInclination: '53.2° LEO',
      qkdStatus: 'ACTIVE_ENTANGLED' as const,
      photonRateQps: 485000,
      linkLatencyMs: 4.2,
      securityState: 'SECURE_MESH' as const,
      activeGroundStation: 'SOC Command Station (Washington D.C.)'
    },
    {
      id: 'SAT-LEO-02',
      name: 'Starlink-Def-Mesh-88',
      constellation: 'STARLINK-GEN3' as const,
      altitudeKm: 540.8,
      orbitInclination: '70.0° Polar',
      qkdStatus: 'ACTIVE_ENTANGLED' as const,
      photonRateQps: 392000,
      linkLatencyMs: 3.8,
      securityState: 'SECURE_MESH' as const,
      activeGroundStation: 'European Defense Node (Frankfurt)'
    },
    {
      id: 'SAT-LEO-03',
      name: 'Kuiper-Secure-Orbit-12',
      constellation: 'KUIPER-MESH' as const,
      altitudeKm: 590.1,
      orbitInclination: '42.0° Equatorial',
      qkdStatus: 'SYNCING' as const,
      photonRateQps: 284000,
      linkLatencyMs: 5.1,
      securityState: 'PQC_ENCLAVE_LOCKED' as const,
      activeGroundStation: 'Indo-Pacific Gateway (Singapore)'
    }
  ];

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Satellite className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              LEO Satellite Mesh & Quantum Key Distribution (QKD)
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
              SPACE TELEMETRY
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Space-to-ground entangled photon telecommunication streams, orbital node status, and FIPS 140-3 Level 4 hardware enclave zero-trust attestation.
          </p>
        </div>
      </div>

      {/* Orbit Telemetry Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono text-xs">
        <div className="command-card p-3.5 space-y-1">
          <span className="text-slate-400 block text-[10px] uppercase">Constellation Health</span>
          <span className="text-xl font-bold text-emerald-400">{telemetry?.constellationHealthScore || 99.2}%</span>
          <span className="text-[10px] text-slate-500 block">Synchronized Mesh</span>
        </div>
        <div className="command-card p-3.5 space-y-1">
          <span className="text-slate-400 block text-[10px] uppercase">Photon Throughput</span>
          <span className="text-xl font-bold text-cyan-400">{telemetry?.totalPhotonThroughput || '1.42 × 10^9'}</span>
          <span className="text-[10px] text-slate-500 block">Photons/sec</span>
        </div>
        <div className="command-card p-3.5 space-y-1">
          <span className="text-slate-400 block text-[10px] uppercase">Space-Ground QKD Lock</span>
          <span className="text-xl font-bold text-purple-300">ACTIVE LOCKED</span>
          <span className="text-[10px] text-slate-500 block">Entangled Pair Stream</span>
        </div>
        <div className="command-card p-3.5 space-y-1">
          <span className="text-slate-400 block text-[10px] uppercase">Hardware Enclave</span>
          <span className="text-sm font-bold text-white truncate block">FIPS 140-3 L4</span>
          <span className="text-[10px] text-emerald-400 block">Attested Secure</span>
        </div>
      </div>

      {/* Orbital Nodes Grid */}
      <div className="command-card p-4 space-y-3">
        <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
          Active Orbital Satellite Nodes
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {nodes.map((node) => (
            <div key={node.id} className="p-3.5 rounded bg-[#101726] border border-[#1C273C] space-y-2 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-cyan-300">{node.name}</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30">
                  {node.constellation}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-1.5 text-[10px] bg-[#090D14] p-2 rounded border border-[#1C273C]">
                <div>
                  <span className="text-slate-400 block">Altitude:</span>
                  <span className="text-white font-bold">{node.altitudeKm} km</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Link Latency:</span>
                  <span className="text-emerald-400 font-bold">{node.linkLatencyMs} ms</span>
                </div>
                <div>
                  <span className="text-slate-400 block">QKD Stream:</span>
                  <span className="text-purple-300 font-bold">{node.qkdStatus}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Photon Rate:</span>
                  <span className="text-cyan-400 font-bold">{node.photonRateQps.toLocaleString()} Qps</span>
                </div>
              </div>

              <div className="text-[10px] text-slate-400 truncate">
                Ground Station: <span className="text-slate-300">{node.activeGroundStation}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
