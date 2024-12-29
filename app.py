from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import matplotlib.pyplot as plt
import io

# Flask uygulaması
app = Flask(__name__)
app.config['SECRET_KEY'] = 'gizli_anahtar'  # Şifreleme için gerekli
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Mehmet1905@localhost/kullanici_yonetimi'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enumerate'i Jinja'ya ekle
app.jinja_env.globals.update(enumerate=enumerate)

# Veritabanı ve şifreleme
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Kullanıcı oturum yönetimi
login_manager = LoginManager(app)
login_manager.login_view = 'giris'
login_manager.login_message = "Bu sayfaya erişmek için lütfen giriş yapın."

# Yükleme klasörü
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Kullanıcı modeli
class Kullanici(db.Model, UserMixin):
    __tablename__ = 'kullanicilar'  # Tablonun adı
    id = db.Column(db.Integer, primary_key=True)
    kullanici_adi = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    sifre = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def kullanici_yukle(kullanici_id):
    return Kullanici.query.get(int(kullanici_id))

# Ana sayfa
@app.route('/')
def ana_sayfa():
    return render_template('index.html')

# Kayıt ol
@app.route('/kayit', methods=['GET', 'POST'])
def kayit():
    if request.method == 'POST':
        kullanici_adi = request.form['kullanici_adi']
        email = request.form['email']
        sifre = bcrypt.generate_password_hash(request.form['sifre']).decode('utf-8')

        yeni_kullanici = Kullanici(kullanici_adi=kullanici_adi, email=email, sifre=sifre)
        db.session.add(yeni_kullanici)
        db.session.commit()

        flash('Hesap başarıyla oluşturuldu! Giriş yapabilirsiniz.', 'success')
        return redirect(url_for('giris'))

    return render_template('kayit.html')

# Giriş yap
@app.route('/giris', methods=['GET', 'POST'])
def giris():
    if request.method == 'POST':
        email = request.form['email']
        sifre = request.form['sifre']
        kullanici = Kullanici.query.filter_by(email=email).first()

        if kullanici and bcrypt.check_password_hash(kullanici.sifre, sifre):
            login_user(kullanici)
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('ana_sayfa'))
        else:
            flash('Giriş başarısız! Lütfen bilgilerinizi kontrol edin.', 'danger')

    return render_template('giris.html')
# Hesabım bölümü
@app.route('/hesap')
@login_required
def hesap():
    return render_template('hesap.html',kullanici=current_user)

# Hesap silme
@app.route('/hesap_sil', methods=['POST'])
@login_required
def hesap_sil():
    try:
        # Mevcut oturumdaki kullanıcıyı veritabanından sil
        db.session.delete(current_user)
        db.session.commit()

        # Kullanıcının oturumunu kapat
        logout_user()
        flash('Hesabınız başarıyla silindi.', 'info')
    except Exception as e:
        # Hata durumunda mesaj döndür
        flash(f'Hesap silme sırasında bir hata oluştu: {e}', 'danger')

    # Giriş sayfasına yönlendir
    return redirect(url_for('giris'))

# Hesap Güncelleme
@app.route('/hesap', methods=['GET', 'POST'])
@login_required
def hesap_guncelle():
    if request.method == 'POST':
        if 'bilgi_guncelle' in request.form:
            yeni_kullanici_adi = request.form['kullanici_adi']
            yeni_email = request.form['email']
            current_user.kullanici_adi = yeni_kullanici_adi
            current_user.email = yeni_email
            db.session.commit()
            flash('Bilgileriniz başarıyla güncellendi!', 'success')

        elif 'sifre_guncelle' in request.form:
            mevcut_sifre = request.form['mevcut_sifre']
            yeni_sifre = request.form['yeni_sifre']
            if bcrypt.check_password_hash(current_user.sifre, mevcut_sifre):
                current_user.sifre = bcrypt.generate_password_hash(yeni_sifre).decode('utf-8')
                db.session.commit()
                flash('Şifreniz başarıyla güncellendi!', 'success')
            else:
                flash('Mevcut şifreniz yanlış!', 'danger')

    return render_template('hesap.html', kullanici=current_user)


# Çıkış yap
@app.route('/cikis')
@login_required
def cikis():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'info')
    return redirect(url_for('giris'))

# Dosya yükleme
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Dosya seçilmedi!', 'danger')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('Dosya seçilmedi!', 'danger')
            return redirect(request.url)

        # Sadece CSV dosyalarını kabul et
        if not file.filename.endswith('.csv'):
            flash('Sadece CSV dosyalarını yükleyebilirsiniz.', 'danger')
            return redirect(request.url)

        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            return redirect(url_for('analyze_file', filename=file.filename))
        except Exception as e:
            flash(f'Dosya yükleme sırasında bir hata oluştu: {e}', 'danger')
            return redirect(request.url)

    return render_template('upload.html')

@app.route('/kullanicilar', methods=['GET', 'POST'])
@login_required
def kullanici_listele():
    # Veritabanından kullanıcıları al
    kullanicilar = Kullanici.query.all()

    # Gizlilik açısından isim ve e-posta maskeleme
    maskeleme = []
    for kullanici in kullanicilar:
        kullanici_adi = kullanici.kullanici_adi[0] + '*' * (len(kullanici.kullanici_adi) - 1)
        email_bolumleri = kullanici.email.split('@')
        email_ilk_kisim = email_bolumleri[0][0] + '*' * (len(email_bolumleri[0]) - 1)
        email = email_ilk_kisim + '@' + email_bolumleri[1]
        maskeleme.append({'kullanici_adi': kullanici_adi, 'email': email})

    toplam = len(kullanicilar)  # Kullanıcı sayısını hesapla

    return render_template('kullanicilar.html', kullanicilar=maskeleme, toplam=toplam)

def train_model():
    temizVeri = pd.read_csv("temiz_veri.csv")

    # Bağımsız ve bağımlı değişkenleri ayır
    X = temizVeri.drop(columns=['attack_cat', 'label'])
    y = temizVeri['attack_cat']

    # Kategorik veriler için One-Hot Encoding uygula
    X = pd.get_dummies(X, columns=['proto', 'service'], drop_first=True)

    # True/False değerlerini 0 ve 1'e çevir
    X = X.astype({col: 'float' for col in X.select_dtypes(include=['bool']).columns})

    # Veriyi normalleştir
    scaler = MinMaxScaler()
    numeric_columns = X.select_dtypes(include=['int64', 'float64']).columns
    X[numeric_columns] = scaler.fit_transform(X[numeric_columns])

    # Etiketleri sayısallaştır
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Eğitim ve test setlerini ayır
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

    # XGBoost modelini tanımla
    xgb_model = XGBClassifier(
        objective='multi:softmax',
        num_class=len(label_encoder.classes_),
        eval_metric='mlogloss',
        use_label_encoder=False
    )

    # XGBoost modelini eğit
    xgb_model.fit(X_train, y_train)

    # Modeli kaydet
    MODEL_PATH = r"C:\Users\Mehmet Ali\Desktop\web projesi\xgb_model.pkl"

    with open(MODEL_PATH, "wb") as f:
        pickle.dump((xgb_model, scaler, label_encoder), f)

app.config['UPLOAD_FOLDER'] = r"C:\Users\Mehmet Ali\Desktop\web projesi\uploads"

MODEL_PATH = r"C:\Users\Mehmet Ali\Desktop\web projesi\xgb_model.pkl"

@app.route('/analyze/<filename>')
@login_required
def analyze_file(filename):
    # Modeli yükle
    with open(r"C:\Users\Mehmet Ali\Desktop\web projesi\xgb_model.pkl", "rb") as f:
        xgb_model, scaler, label_encoder = pickle.load(f)

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    data = pd.read_csv(file_path)

    # Veri işleme
    X = pd.get_dummies(data, columns=['proto', 'service'], drop_first=True)
    X = X.astype({col: 'float' for col in X.select_dtypes(include=['bool']).columns})

    # Eksik kolonları doldur (One-Hot Encoding farklılıkları nedeniyle)
    for col in scaler.feature_names_in_:
        if col not in X.columns:
            X[col] = 0
    X = X[scaler.feature_names_in_]  # Kolon sırasını düzenle

    # Veriyi ölçeklendir
    X = scaler.transform(X)

    # Tahmin yap
    predictions = xgb_model.predict(X)
    predicted_classes = label_encoder.inverse_transform(predictions)

    # Sonuçları bir DataFrame olarak hazırla
    data['Prediction'] = predicted_classes

    # Saldırı kategorilerini özetle
    attack_counts = data['Prediction'].value_counts()

    # Toplam ve normal trafik sayıları
    total_traffic = len(data)
    normal_traffic = attack_counts.get('Normal', 0)
    security_score = normal_traffic / total_traffic * 100

    # Güvenlik durumu belirleme
    if security_score > 80:
        security_status = "Ağınız Güvenli"
    elif 50 <= security_score <= 80:
        security_status = "Ağınız Orta Derece Güvenli"
    else:
        security_status = "Ağınız Güvenli Değil"

    # Saldırı sayıları grafiği oluştur
    fig, ax = plt.subplots(figsize=(10, 6))
    attack_counts_sorted = attack_counts.sort_values(ascending=False)
    ax.bar(attack_counts_sorted.index, attack_counts_sorted.values, color='orange')
    ax.set_title("Tespit Edilen Saldırı Türleri ve Sayıları")
    ax.set_xlabel("Saldırı Türleri")
    ax.set_ylabel("Sayı")
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Grafiği bir dosyaya kaydet
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)

    # Kullanıcıya sonuçları döndür
    return render_template(
        'sonuc.html',
        attack_counts=attack_counts.to_dict(),
        total_traffic=total_traffic,
        security_score=round(security_score, 2),
        security_status=security_status,
        graph=buf
    )

# Uygulamayı çalıştır
if __name__ == '__main__':
    app.run(debug=True)
