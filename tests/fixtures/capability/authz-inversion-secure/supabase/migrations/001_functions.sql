create or replace function public.change_grade(target_student uuid, new_grade text)
returns void
language plpgsql
security invoker
as $$
begin
  if auth.role() <> 'authenticated' or auth.uid() is null then
    raise exception 'authenticated teacher authorization required';
  end if;
  update public.grades
  set grade = new_grade
  where student_id = target_student
    and teacher_id = auth.uid();
end;
$$;

revoke execute on function public.change_grade(uuid, text) from anon;
grant execute on function public.change_grade(uuid, text) to authenticated;
