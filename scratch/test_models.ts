import dotenv from 'dotenv';
dotenv.config();
import { GoogleGenAI } from '@google/genai';

async function testModels() {
  const apiKey = process.env.GEMINI_API_KEY || '';
  const ai = new GoogleGenAI({ apiKey });

  const modelsToTest = [
    'gemini-2.5-flash',
    'gemini-2.0-flash',
    'gemini-1.5-flash',
    'gemini-2.5-pro',
    'gemini-2.5-flash',
    'gemini-2.0-flash-lite'
  ];

  for (const m of modelsToTest) {
    try {
      console.log(`Testing model "${m}"...`);
      const res = await ai.models.generateContent({
        model: m,
        contents: 'Say OK',
      });
      console.log(`SUCCESS for "${m}":`, res.text?.trim());
    } catch (err: any) {
      console.log(`FAILED for "${m}":`, err.message || err);
    }
  }
}

testModels();
