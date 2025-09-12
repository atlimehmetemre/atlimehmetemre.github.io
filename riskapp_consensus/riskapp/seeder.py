from models import db, Suggestion

DEFAULT_SUGGESTIONS = {
    "Tedarik": [
        "Yerli üreticilerle alternatif tedarik kanalları oluştur.",
        "Kritik parçaları proje başlangıcında stokla.",
        "Ödeme planlarını netleştir ve zamanında yap.",
        "Teslimatları kademelendir ve erken uyarı eşikleri belirle."
    ],
    "Planlama": [
        "Kritik yol analizi ve tampon süre ekle.",
        "Bağımlılıkları görünür kılacak bir Gantt güncelleme ritmi oluştur.",
        "Değişiklik yönetimi onay kapıları tanımla."
    ],
    "Kalite": [
        "Tedarikçi kabul testlerini standardize et.",
        "Giriş kalite kontrol örneklemesini artır.",
        "Hata kök neden analizi (5N1K/Fishbone) uygula."
    ]
}

def seed_if_empty():
    if Suggestion.query.count() == 0:
        for cat, items in DEFAULT_SUGGESTIONS.items():
            for t in items:
                db.session.add(Suggestion(category=cat, text=t))
        db.session.commit()
