import React, { useState, useRef } from 'react';
import { 
  Video, UploadCloud, File, AlertTriangle, ShieldCheck, CheckCircle2, 
  Trash2, RefreshCw, Sparkles, Activity, Eye, Mic, Download, Play, Music, Copy, Check
} from 'lucide-react';
import { DeepfakeForensicsResult } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface DeepfakeDetectionViewProps {
  token: string;
  onAnalyzeMedia: (file: File) => Promise<DeepfakeForensicsResult | null>;
  onAnalyzeSample: (sampleName: string, mediaType: 'image' | 'audio' | 'video') => Promise<DeepfakeForensicsResult | null>;
  currentResult: DeepfakeForensicsResult | null;
  loading: boolean;
  error: string | null;
}

export default function DeepfakeDetectionView({
  token,
  onAnalyzeMedia,
  onAnalyzeSample,
  currentResult,
  loading,
  error
}: DeepfakeDetectionViewProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePreview, setFilePreview] = useState<string | null>(null);
  const [fileType, setFileType] = useState<'image' | 'video' | 'audio' | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const MAX_FILE_SIZE = 15 * 1024 * 1024; // 15MB

  const handleFileProcess = (file: File) => {
    setValidationError(null);

    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
      setValidationError(`Selected file exceeds maximum limit of 15MB (File size: ${(file.size / (1024 * 1024)).toFixed(2)} MB).`);
      return;
    }

    // Determine media type
    let detected: 'image' | 'video' | 'audio' | null = null;
    if (file.type.startsWith('image/')) detected = 'image';
    else if (file.type.startsWith('video/')) detected = 'video';
    else if (file.type.startsWith('audio/')) detected = 'audio';
    else {
      const ext = file.name.split('.').pop()?.toLowerCase();
      if (['png', 'jpg', 'jpeg', 'webp'].includes(ext || '')) detected = 'image';
      else if (['mp4', 'webm'].includes(ext || '')) detected = 'video';
      else if (['mp3', 'wav'].includes(ext || '')) detected = 'audio';
    }

    if (!detected) {
      setValidationError('Unsupported format. Please select an image (PNG, JPG, WEBP), video (MP4, WEBM), or audio file (MP3, WAV).');
      return;
    }

    setSelectedFile(file);
    setFileType(detected);

    // Create preview URL
    const previewUrl = URL.createObjectURL(file);
    setFilePreview(previewUrl);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileProcess(e.dataTransfer.files[0]);
    }
  };

  const handleRemoveFile = () => {
    if (filePreview) {
      URL.revokeObjectURL(filePreview);
    }
    setSelectedFile(null);
    setFilePreview(null);
    setFileType(null);
    setValidationError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleSubmitAnalysis = async () => {
    if (!selectedFile) return;
    await onAnalyzeMedia(selectedFile);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Video className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              Neural Deepfake & Generative Media Forensics
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
              AI FORENSICS LAB
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Inspect images, videos, and voice recordings for synthetic generative artifacts, transposed FFT spectral convolution anomalies, and Remote Photoplethysmography (rPPG) subdermal blood flow pulse failure.
          </p>
        </div>

        {/* 1-Click Samples */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Presets:</span>
          <button
            onClick={() => onAnalyzeSample('synthetic_executive_stream.mp4', 'video')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-red-500/30 text-red-300 text-[10px] font-mono transition-colors"
          >
            🚨 Synthetic Stream (Deepfake)
          </button>
          <button
            onClick={() => onAnalyzeSample('cloned_executive_voice.mp3', 'audio')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-amber-500/30 text-amber-300 text-[10px] font-mono transition-colors"
          >
            🎙️ Voice Clone Note
          </button>
          <button
            onClick={() => onAnalyzeSample('authentic_press_conference.png', 'image')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-emerald-500/30 text-emerald-300 text-[10px] font-mono transition-colors"
          >
            🟢 Authentic Camera Capture
          </button>
        </div>
      </div>

      {/* Main Grid: Upload Dropzone & Live Inspection */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Media Upload Area (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-3.5">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white flex items-center justify-between">
              <span>Select Media Asset for Forensics</span>
              <span className="text-[10px] font-mono text-slate-400">MAX: 15MB</span>
            </h3>

            {/* Drag & Drop Box */}
            {!selectedFile ? (
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
                  dragActive 
                    ? 'border-purple-500 bg-purple-500/10' 
                    : 'border-[#1E2B42] hover:border-purple-500/50 hover:bg-[#111A2E]'
                }`}
              >
                <div className="w-12 h-12 rounded-full bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 mb-3">
                  <UploadCloud className="w-6 h-6 animate-pulse" />
                </div>
                <div className="font-sans text-xs font-semibold text-slate-200">
                  Drag & drop media file here, or click to browse
                </div>
                <div className="font-mono text-[10px] text-slate-400 mt-1">
                  Supports Images (PNG, JPG, WEBP), Videos (MP4, WEBM), Audio (MP3, WAV)
                </div>

                <button
                  type="button"
                  className="mt-4 px-3 py-1.5 rounded-md bg-purple-600 hover:bg-purple-500 text-white font-sans text-xs font-semibold shadow-[0_0_12px_rgba(168,85,247,0.3)] transition-colors pointer-events-none"
                >
                  Choose Media File
                </button>
              </div>
            ) : (
              /* Selected File Preview Card */
              <div className="bg-[#101726] border border-purple-500/40 rounded-lg p-3.5 space-y-3">
                {/* Live Preview Element */}
                <div className="rounded-md bg-[#090D14] border border-[#1C273C] p-2 flex items-center justify-center max-h-56 overflow-hidden">
                  {fileType === 'image' && filePreview && (
                    <img 
                      src={filePreview} 
                      alt="Selected media preview" 
                      className="max-h-48 rounded object-contain"
                    />
                  )}
                  {fileType === 'video' && filePreview && (
                    <video 
                      src={filePreview} 
                      controls 
                      className="max-h-48 w-full rounded"
                    />
                  )}
                  {fileType === 'audio' && filePreview && (
                    <div className="w-full py-4 px-2 space-y-2">
                      <div className="flex items-center gap-2 text-purple-400 justify-center">
                        <Music className="w-6 h-6 animate-pulse" />
                        <span className="font-mono text-xs">Audio Waveform Stream Loaded</span>
                      </div>
                      <audio src={filePreview} controls className="w-full" />
                    </div>
                  )}
                </div>

                {/* File Metadata Info */}
                <div className="space-y-1 text-xs font-mono">
                  <div className="flex justify-between items-center text-slate-300">
                    <span className="text-slate-400">File Name:</span>
                    <span className="font-bold text-white truncate max-w-[200px]" title={selectedFile.name}>
                      {selectedFile.name}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-slate-300">
                    <span className="text-slate-400">Size:</span>
                    <span className="text-cyan-400">{formatFileSize(selectedFile.size)}</span>
                  </div>
                  <div className="flex justify-between items-center text-slate-300">
                    <span className="text-slate-400">MIME Type:</span>
                    <span className="text-purple-300 uppercase">{selectedFile.type || 'Binary Media'}</span>
                  </div>
                </div>

                {/* Controls */}
                <div className="flex items-center gap-2 pt-1">
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="flex-1 py-1.5 px-2 rounded bg-[#162136] hover:bg-[#1E2D48] text-slate-300 text-xs font-mono text-center border border-[#202E48] transition-colors"
                  >
                    Replace File
                  </button>
                  <button
                    onClick={handleRemoveFile}
                    className="p-1.5 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 transition-colors"
                    title="Remove file"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {/* Hidden Native File Input */}
            <input
              ref={fileInputRef}
              type="file"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileProcess(e.target.files[0]);
                }
              }}
              accept="image/png,image/jpeg,image/webp,video/mp4,video/webm,audio/mpeg,audio/wav"
              className="hidden"
            />

            {/* Validation Error Banner */}
            {validationError && (
              <div className="p-2.5 rounded bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-mono flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <span>{validationError}</span>
              </div>
            )}

            {/* Error Banner */}
            {error && (
              <div className="p-2.5 rounded bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-mono flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <span>{error}</span>
              </div>
            )}

            {/* Primary Action Button */}
            <button
              onClick={handleSubmitAnalysis}
              disabled={!selectedFile || loading}
              className={`w-full py-2.5 px-4 rounded-md font-sans text-xs font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
                !selectedFile || loading
                  ? 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed'
                  : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-[0_0_15px_rgba(168,85,247,0.4)] cursor-pointer'
              }`}
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  <span>Executing FFT & rPPG Forensics...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-purple-200" />
                  <span>Analyze Media Payload</span>
                </>
              )}
            </button>

            {/* Zero Retention Guarantee Pill */}
            <div className="text-[10px] font-mono text-slate-400 text-center flex items-center justify-center gap-1.5 pt-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Strict Zero-Retention: Media payload inspected transiently and purged from RAM.</span>
            </div>
          </div>
        </div>

        {/* Right Column: Forensic Results & Evidence (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {!currentResult ? (
            <div className="command-card p-8 flex flex-col items-center justify-center text-center space-y-3 min-h-[360px]">
              <div className="w-14 h-14 rounded-full bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <Eye className="w-7 h-7" />
              </div>
              <h4 className="text-sm font-bold font-sans text-white">
                No Media Forensics Executed Yet
              </h4>
              <p className="text-xs text-slate-400 max-w-md font-sans">
                Upload any image, video, or audio file on the left or select a 1-click test preset above to execute biometric rPPG, FFT frequency anomaly, and generative latent analysis.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Verdict Summary Card */}
              <div className="command-card p-4 space-y-3 border-purple-500/30">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1C273C] pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400 uppercase">Analysis Target:</span>
                      <span className="font-mono text-xs font-bold text-white truncate max-w-xs" title={currentResult.targetName}>
                        {currentResult.targetName}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      Evaluated: {new Date(currentResult.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <StatusBadge 
                    status={currentResult.classification} 
                    severity={
                      currentResult.syntheticConfidence === null 
                        ? (currentResult.generativeMetadataDetected && currentResult.generativeMetadataDetected.length > 0 ? 'high' : 'medium')
                        : (currentResult.syntheticConfidence > 70 ? 'critical' : (currentResult.syntheticConfidence > 30 ? 'high' : 'low'))
                    } 
                    size="md"
                  />
                </div>

                {/* Neural Model Status Notice if Unconfigured */}
                {currentResult.syntheticConfidence === null && (
                  <div className="p-3 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono space-y-1">
                    <div className="flex items-center gap-1.5 font-bold">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      <span>NEURAL INFERENCE ENGINE NOT CONFIGURED</span>
                    </div>
                    <p className="text-[11px] text-slate-300 font-sans">
                      Deep learning weights (PyTorch/ONNX) or external generative vision API are not configured. CyberGuard does not invent fake confidence percentages. Performed deterministic cryptographic hashing, Shannon entropy, magic byte verification, and embedded metadata inspection.
                    </p>
                  </div>
                )}

                {/* Confidence Meter Bar (when model is configured) */}
                {currentResult.syntheticConfidence !== null ? (
                  <div className="space-y-1.5">
                    <div className="flex justify-between items-center text-xs font-mono">
                      <span className="text-slate-300">Synthetic Deepfake Probability:</span>
                      <span className={`font-bold ${
                        currentResult.syntheticConfidence > 70 ? 'text-red-400' : (currentResult.syntheticConfidence > 30 ? 'text-amber-400' : 'text-emerald-400')
                      }`}>
                        {currentResult.syntheticConfidence}% CONFIDENCE
                      </span>
                    </div>
                    <div className="w-full h-2.5 bg-[#090D14] border border-[#1C273C] rounded-full overflow-hidden flex">
                      <div 
                        className={`h-full transition-all duration-500 ${
                          currentResult.syntheticConfidence > 70 
                            ? 'bg-gradient-to-r from-red-600 to-red-400 shadow-[0_0_10px_#EF4444]' 
                            : (currentResult.syntheticConfidence > 30 
                              ? 'bg-gradient-to-r from-amber-600 to-amber-400' 
                              : 'bg-gradient-to-r from-emerald-600 to-emerald-400')
                        }`}
                        style={{ width: `${Math.max(currentResult.syntheticConfidence, 5)}%` }}
                      />
                    </div>
                  </div>
                ) : null}

                {/* Key Forensic Indicator Badges */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-[10px]">
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">FFT Spectral Anomaly</span>
                    <span className={`font-bold text-xs ${
                      currentResult.spectralAnomalyScore !== null 
                        ? (currentResult.spectralAnomalyScore > 30 ? 'text-red-400' : 'text-emerald-400')
                        : 'text-slate-400'
                    }`}>
                      {currentResult.spectralAnomalyScore !== null ? `${currentResult.spectralAnomalyScore}%` : 'N/A (No Model)'}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">rPPG Biometric Pulse</span>
                    <span className={`font-bold text-xs ${
                      currentResult.rppgPulseDetected !== null
                        ? (currentResult.rppgPulseDetected ? 'text-emerald-400' : 'text-red-400')
                        : 'text-slate-400'
                    }`}>
                      {currentResult.rppgPulseDetected !== null
                        ? (currentResult.rppgPulseDetected ? 'CONFIRMED' : 'DEAD / SYNTHETIC')
                        : 'N/A (No Pulse Model)'}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Format Detected</span>
                    <span className="font-bold text-xs text-cyan-400">
                      {currentResult.detectedFormat || currentResult.mediaType.toUpperCase()}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Entropy</span>
                    <span className="font-bold text-xs text-purple-300">
                      {currentResult.entropy !== undefined ? `${currentResult.entropy.toFixed(2)} / 8.0` : 'N/A'}
                    </span>
                  </div>
                </div>

                {/* File Hash & Entropy details if available */}
                {(currentResult.sha256Hash || currentResult.fileSizeBytes) && (
                  <div className="bg-[#090D15] border border-[#1C273C] rounded p-2.5 font-mono text-[10px] space-y-1 text-slate-300">
                    {currentResult.fileSizeBytes && (
                      <div className="flex justify-between">
                        <span className="text-slate-400">Payload File Size:</span>
                        <span className="text-slate-200 font-bold">{formatFileSize(currentResult.fileSizeBytes)}</span>
                      </div>
                    )}
                    {currentResult.sha256Hash && (
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-slate-400 shrink-0">SHA-256:</span>
                        <div className="flex items-center gap-1.5 overflow-hidden">
                          <span className="text-cyan-400 truncate max-w-xs">{currentResult.sha256Hash}</span>
                          <button
                            onClick={() => copyToClipboard(currentResult.sha256Hash!)}
                            className="p-1 text-slate-400 hover:text-white"
                            title="Copy SHA-256"
                          >
                            {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Red Flags / Identified Discrepancies */}
              {currentResult.redFlags && currentResult.redFlags.length > 0 && (
                <div className="command-card p-4 space-y-2">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Identified Anomalies & Forensic Flags</span>
                  </h4>
                  <ul className="space-y-1.5 text-xs font-sans text-slate-300">
                    {currentResult.redFlags.map((flag, idx) => (
                      <li key={idx} className="flex items-start gap-2 bg-[#101726] border border-[#1C273C] p-2 rounded">
                        <span className="text-red-400 font-mono font-bold">•</span>
                        <span>{flag}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Structured Forensic Evidence Table */}
              <div className="command-card p-4 space-y-3">
                <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                  Deterministic Biometric & Spectral Evidence Table
                </h4>
                <div className="overflow-x-auto rounded border border-[#1C273C]">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-[#101728] border-b border-[#1C273C] text-[10px] font-mono uppercase tracking-wider text-slate-400">
                        <th className="py-2 px-3">Metric</th>
                        <th className="py-2 px-3">Measured Telemetry</th>
                        <th className="py-2 px-3">Natural Baseline</th>
                        <th className="py-2 px-3 text-right">Verdict</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1C273C]/60 font-sans">
                      {currentResult.forensicEvidence.map((ev, idx) => (
                        <tr key={idx} className="hover:bg-[#131D31] transition-colors">
                          <td className="py-2 px-3 font-medium text-slate-200">
                            {ev.metric}
                          </td>
                          <td className="py-2 px-3 font-mono text-[11px] text-slate-300">
                            {ev.measured}
                          </td>
                          <td className="py-2 px-3 font-mono text-[11px] text-slate-400">
                            {ev.baseline}
                          </td>
                          <td className="py-2 px-3 text-right">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase border ${
                              ev.status === 'clean' 
                                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' 
                                : 'bg-red-500/15 text-red-400 border-red-500/30'
                            }`}>
                              {ev.status === 'clean' ? 'PASS' : 'ANOMALY'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
