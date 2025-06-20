# -
 פרוייקט לבגרות במדמח על מערכת לניהול אנשים על הספקטרום האוטיסטי
# מערכת ניהול משתמשים ופרופילים – GUI עם Tkinter

מערכת זו נועדה לאפשר ניהול משתמשים ופרופילים דרך ממשק גרפי נוח, כולל התממשקות לשרת TCP לצורך הרשאות, הרשמה, התחברות, וניהול הרשאות משתמשים.

---

##  תכונות עיקריות

- **הרשמה והתחברות** עם סיסמה מוצפנת (bcrypt)
- **חלוקה לרמות גישה**:
  - Admin – יכול להוסיף, למחוק ולעדכן פרופילים, לנהל משתמשים
  - Worker – יכול לצפות בפרופילים בלבד
- **ניהול פרופילים**: הוספה, מחיקה, עדכון התנהגות
- **ניהול משתמשים**: שינוי תפקידים, סינון לפי תפקיד, מחיקה
- **הגנה בסיסית**:
  - הגנה מ־SQL Injection
  - חסימת משתמש לאחר 3 ניסיונות כושלים (נעילה ל־60 שניות)
  - סיסמאות מוצפנות עם bcrypt

---

##  מבנה הקבצים

| קובץ | תיאור |
|------|--------|
| `Server.py` | שרת TCP שמטפל בבקשות: login, register, get_users ועוד |
| `auth_and_crud.py` | פונקציות העזר: הוספה/מחיקה/עדכון פרופילים |
| `database.db` | מסד נתונים SQLite (נוצר אוטומטית) |
| `gui_main.py` | מראה את הכל המסך |
| `README.md` | קובץ הסבר זה |

---

##  התקנה והרצה

1. **התקנת ספריות דרושות**:
```bash
pip install bcrypt
pip install tkinter
pip install socket
pip install threading
pip install json
pip install sqlite3
pip install time
```
2. **הרצת database.db**
3. **הרצת auth_and_crud.py**
4. **הרצת הgui_main.py**

## בדיקות
ניתן לבדוק את מערכת ההתחברות וההרשמה.

נסה ליצור משתמש Worker ולוודא שאין לו גישה לניהול משתמשים.

נסה שלושה ניסיונות כושלים כדי לבדוק חסימה זמנית.

## אבטחה
המערכת משתמשת בהצפנת סיסמה עם bcrypt.

יש הגנה מפני SQL Injection.

ניסיון התחברות שגוי ננעל לאחר 3 ניסיונות למשך דקה.

