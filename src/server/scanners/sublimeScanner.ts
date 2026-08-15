import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import util from 'util';

const execPromise = util.promisify(exec);

export interface SublimeAnalysisResult {
  totalRulesEvaluated: number;
  flaggedCount: number;
  flaggedRules: {
    name: string;
    severity: string;
    source?: string;
  }[];
}

/**
 * Execute Sublime Security YML Rule Engine against an EML message input.
 * Security Reasoning: Evaluates 1,100+ community & enterprise threat rules (MQL queries)
 * to detect spear phishing, credential harvesting, brand impersonation, and BEC tactics.
 */
export async function runSublimeAnalysis(emlContent: string | Buffer): Promise<SublimeAnalysisResult | null> {
  const rulesDir = path.join(process.cwd(), 'sublime-rules', 'detection-rules');
  if (!fs.existsSync(rulesDir)) {
    console.warn('[SublimeScanner] Rules directory not found at:', rulesDir);
    return null;
  }

  const runnerPath = path.join(process.cwd(), 'src', 'server', 'scanners', 'sublime_runner.py');
  if (!fs.existsSync(runnerPath)) {
    console.warn('[SublimeScanner] Runner script not found at:', runnerPath);
    return null;
  }

  const tempDir = path.join(process.cwd(), 'data', 'temp');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  const tempFilePath = path.join(tempDir, `scan_${Date.now()}_${Math.random().toString(36).substring(7)}.eml`);

  try {
    if (Buffer.isBuffer(emlContent)) {
      fs.writeFileSync(tempFilePath, emlContent);
    } else {
      fs.writeFileSync(tempFilePath, String(emlContent), 'utf8');
    }

    const uvPath = path.join(process.env.USERPROFILE || '', '.local', 'bin', 'uv.exe');

    let command = '';
    if (fs.existsSync(uvPath)) {
      command = `"${uvPath}" run --with sublime-cli --python 3.11 "${runnerPath}" "${tempFilePath}" "${rulesDir}"`;
    } else {
      command = `python "${runnerPath}" "${tempFilePath}" "${rulesDir}"`;
    }

    const env = {
      ...process.env,
      PYTHONIOENCODING: 'utf-8'
    };

    const { stdout } = await execPromise(command, { env, maxBuffer: 10 * 1024 * 1024, timeout: 35000 });
    
    if (!stdout || !stdout.trim()) {
      return null;
    }

    const jsonStartIdx = stdout.indexOf('{');
    let jsonStr = stdout;
    if (jsonStartIdx !== -1) {
      jsonStr = stdout.substring(jsonStartIdx);
    }

    const parsedData = JSON.parse(jsonStr);
    if (parsedData.error) {
      console.warn('[SublimeScanner] Sublime runner returned error:', parsedData.error);
    }

    return {
      totalRulesEvaluated: parsedData.totalRulesEvaluated || 0,
      flaggedCount: parsedData.flaggedCount || 0,
      flaggedRules: Array.isArray(parsedData.flaggedRules) ? parsedData.flaggedRules : []
    };
  } catch (err: any) {
    console.warn('[SublimeScanner] Execution warning:', err.message || err);
    return null;
  } finally {
    try {
      if (fs.existsSync(tempFilePath)) {
        fs.unlinkSync(tempFilePath);
      }
    } catch (e) {}
  }
}
