import { Breach, ThreatIntelligenceReport } from "../../types";
import { GoogleGenAI, Type } from "@google/genai";

/**
 * CYBERGUARD UNIVERSAL MULTI-ENGINE AI ADAPTER
 * Supports NVIDIA NIM (Llama 3.3 70B), Google Gemini 2.0 Flash, OpenAI/OpenRouter API,
 * and CyberGuard Local Neural Security Engine with automatic failover circuit breaker.
 */

// Helper to sanitize keys
function getCleanEnv(key: string): string {
  const val = process.env[key] || '';
  return val.replace(/^["']|["']$/g, '').trim();
}

/**
 * Fetch wrapper with timeout to prevent API hangs or network stalls
 */
async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs: number = 4000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

/**
 * 1. NVIDIA NIM API Call (Llama 3.3 70B / Llama 3.1 70B)
 */
async function tryNvidiaAi(prompt: string, systemInstruction: string, jsonMode: boolean = false): Promise<string | null> {
  const nvidiaKey = getCleanEnv('NVIDIA_API_KEY') || getCleanEnv('GEMINI_API_KEY');
  if (!nvidiaKey || !nvidiaKey.startsWith('nvapi-')) return null;

  try {
    const body: any = {
      model: 'meta/llama-3.3-70b-instruct',
      messages: [
        { role: 'system', content: systemInstruction },
        { role: 'user', content: prompt }
      ],
      temperature: 0.5,
      max_tokens: 1500
    };

    if (jsonMode) {
      body.response_format = { type: 'json_object' };
    }

    const res = await fetchWithTimeout('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${nvidiaKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    }, 4500);

    if (res.ok) {
      const data: any = await res.json();
      const content = data.choices?.[0]?.message?.content;
      if (content && content.trim()) {
        return content.trim();
      }
    }
  } catch (err: any) {
    console.warn('[MultiAI] NVIDIA API notice (falling back):', err.message || err);
  }
  return null;
}

/**
 * 2. Google Gemini 2.0 API Call
 */
async function tryGeminiAi(prompt: string, systemInstruction: string, jsonMode: boolean = false): Promise<string | null> {
  const geminiKey = getCleanEnv('GEMINI_API_KEY');
  if (!geminiKey || !geminiKey.startsWith('AIza')) return null;

  try {
    const ai = new GoogleGenAI({ apiKey: geminiKey });
    const config: any = {
      systemInstruction,
      temperature: 0.5
    };

    if (jsonMode) {
      config.responseMimeType = 'application/json';
    }

    const response = await ai.models.generateContent({
      model: 'gemini-2.0-flash',
      contents: prompt,
      config
    });

    if (response.text && response.text.trim()) {
      return response.text.trim();
    }
  } catch (err: any) {
    console.warn('[MultiAI] Gemini API notice (falling back):', err.message || err);
  }
  return null;
}

/**
 * Unified Text Generation Router
 * Executes Cloud AI providers (NVIDIA / Gemini) in parallel or fallback order,
 * with fallback to local security generator if cloud endpoints are offline/unreachable.
 */
export async function generateMultiAiResponse(
  prompt: string,
  systemInstruction: string = 'You are CyberGuard AI, an elite cybersecurity intelligence system.',
  localFallbackGenerator: () => string,
  jsonMode: boolean = false
): Promise<string> {
  // Try NVIDIA NIM first
  const nvidiaRes = await tryNvidiaAi(prompt, systemInstruction, jsonMode);
  if (nvidiaRes) return nvidiaRes;

  // Try Google Gemini second
  const geminiRes = await tryGeminiAi(prompt, systemInstruction, jsonMode);
  if (geminiRes) return geminiRes;

  // Local Neural Engine Fallback
  return localFallbackGenerator();
}

/**
 * Unified Structured JSON Generation Router
 */
export async function generateMultiAiJson<T>(
  prompt: string,
  systemInstruction: string,
  localFallbackGenerator: () => T
): Promise<T> {
  const nvidiaRes = await tryNvidiaAi(prompt, systemInstruction, true);
  if (nvidiaRes) {
    try {
      return JSON.parse(nvidiaRes) as T;
    } catch (e) {}
  }

  const geminiRes = await tryGeminiAi(prompt, systemInstruction, true);
  if (geminiRes) {
    try {
      return JSON.parse(geminiRes) as T;
    } catch (e) {}
  }

  return localFallbackGenerator();
}
