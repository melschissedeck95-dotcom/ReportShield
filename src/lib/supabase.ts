import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://mduiryhebpgtnbxdnvjm.supabase.co";
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "sb_publishable_rEgO_kVN_KvMy927OnXWog_LV5VcH8K";

export const supabase = createClient(supabaseUrl, supabaseAnonKey);
