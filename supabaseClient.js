// supabaseClient.js
// Supabase client for frontend reads (anon key only)
// IMPORTANT: never expose service_role keys on the frontend
// For admin operations, use serverless functions (see functions/ dir) to avoid exposing service_role key.
// Enable RLS on 'products' table: e.g., allow anon reads (select *), but restrict inserts/updates/deletes to authenticated admins via policies like (auth.role() = 'authenticated' and auth.uid() = user_id) or service_role in backend.
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

const SUPABASE_URL = 'https://qqlnkaheqedrhwtcrqob.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFxbG5rYWhlcWVkcmh3dGNycW9iIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTkxMjg2NjIsImV4cCI6MjA3NDcwNDY2Mn0.rM7SK68xk4ipGU2FSTwh7LaWVTmGmzMYJmJ4Iw3bqjQ';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
export default supabase;
