# Payment ABE Attribute Update Fix - TODO Steps

## Approved Plan Summary
Fix payment → ABE access issue by re-generating user private key with \"paid:true\" attribute after successful payment.

## Steps (Completed as marked)

### 1. ✅ Create TODO.md

### 2. ✅ Add `get_user_attributes_base(user_row)` helper to `db.py`

### 3. ✅ Update `routes/user.py` process_payment()
   - Success: update paid_dues → refresh user row → attributes → re-keygen → save key

### 4. ✅ Update `routes/admin.py` user creation
   - Use `get_user_attributes_base()` instead of manual list

### 5. Test the fix
   - Login non-admin user → /user/payment → process payment → /user/resources (access granted?)
   - Check dashboard attributes include \"paid:true\"
   - Test WiFi request_access()

### 6. ✅ Update TODO.md → attempt_completion

**Changes complete. Ready for testing.**

