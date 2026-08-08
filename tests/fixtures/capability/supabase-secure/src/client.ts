import { createClient } from '@supabase/supabase-js';

export const db = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);
export const listMine = () => db.from('api_tokens').select('*');
