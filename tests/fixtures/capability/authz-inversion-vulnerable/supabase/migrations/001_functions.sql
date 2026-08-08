create or replace function public.change_grade(target_student uuid, new_grade text)
returns void
language plpgsql
security definer
as $$
begin
  -- The intended rule is authenticated teachers only. This condition rejects
  -- teachers, then falls through for anonymous callers.
  if auth.role() = 'authenticated' then
    raise exception 'teacher authorization required';
  end if;
  update public.grades set grade = new_grade where student_id = target_student;
end;
$$;

grant execute on function public.change_grade(uuid, text) to anon, authenticated;
