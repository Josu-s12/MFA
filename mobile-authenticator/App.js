import { CameraView, useCameraPermissions } from 'expo-camera';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import { Alert, Pressable, SafeAreaView, StyleSheet, Text, TextInput, View } from 'react-native';
import { parseOtpauth, secondsRemaining, totp } from './totp';

export default function App() {
  const [secret, setSecret] = useState(null);
  const [label, setLabel] = useState('');
  const [manual, setManual] = useState('');
  const [scanning, setScanning] = useState(false);
  const [now, setNow] = useState(Math.floor(Date.now() / 1000));
  const [permission, requestPermission] = useCameraPermissions();

  useEffect(() => {
    const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 250);
    return () => clearInterval(id);
  }, []);

  const save = (s, l = '') => {
    try {
      totp(s); // valida Base32
      setSecret(s.replace(/\s/g, '').toUpperCase());
      setLabel(l);
      setScanning(false);
    } catch (e) {
      Alert.alert('Semilla inválida', e.message);
    }
  };

  const onScan = ({ data }) => {
    const p = parseOtpauth(data);
    if (p) save(p.secret, p.label);
  };

  const startScan = async () => {
    if (!permission?.granted) {
      const r = await requestPermission();
      if (!r.granted) return Alert.alert('Se necesita permiso de cámara');
    }
    setScanning(true);
  };

  const remaining = secondsRemaining(now);
  const code = secret ? totp(secret, now) : null;

  if (scanning) {
    return (
      <SafeAreaView style={styles.container}>
        <CameraView style={{ flex: 1, width: '100%' }} barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
          onBarcodeScanned={onScan} />
        <Pressable style={styles.btn} onPress={() => setScanning(false)}><Text style={styles.btnText}>Cancelar</Text></Pressable>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      <Text style={styles.title}>Mi Authenticator</Text>
      {secret ? (
        <View style={styles.card}>
          <Text style={styles.label}>{label}</Text>
          <Text style={styles.code}>{code.slice(0, 3)} {code.slice(3)}</Text>
          <View style={styles.barBg}><View style={[styles.bar, { width: `${(remaining / 30) * 100}%`, backgroundColor: remaining <= 5 ? '#ff5252' : '#4caf50' }]} /></View>
          <Text style={styles.sec}>{remaining}s</Text>
          <Pressable onPress={() => setSecret(null)}><Text style={styles.link}>Quitar cuenta</Text></Pressable>
        </View>
      ) : (
        <View style={styles.card}>
          <Pressable style={styles.btn} onPress={startScan}><Text style={styles.btnText}>Escanear QR</Text></Pressable>
          <Text style={styles.or}>o pega la semilla Base32</Text>
          <TextInput style={styles.input} value={manual} onChangeText={setManual} autoCapitalize="characters"
            autoCorrect={false} placeholder="JBSWY3DPEHPK3PXP" placeholderTextColor="#777" />
          <Pressable style={styles.btn} onPress={() => save(manual, 'Cuenta manual')}><Text style={styles.btnText}>Guardar</Text></Pressable>
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#121212', alignItems: 'center', justifyContent: 'center', padding: 16 },
  title: { color: '#fff', fontSize: 22, fontWeight: '600', marginBottom: 24 },
  card: { width: '100%', backgroundColor: '#1e1e1e', borderRadius: 12, padding: 20, alignItems: 'center' },
  label: { color: '#aaa', marginBottom: 8 },
  code: { color: '#fff', fontSize: 56, fontWeight: '700', letterSpacing: 4, fontVariant: ['tabular-nums'] },
  barBg: { width: '100%', height: 8, backgroundColor: '#333', borderRadius: 4, marginTop: 16, overflow: 'hidden' },
  bar: { height: 8 },
  sec: { color: '#aaa', marginTop: 8 },
  link: { color: '#64b5f6', marginTop: 20 },
  btn: { backgroundColor: '#3949ab', paddingVertical: 12, paddingHorizontal: 24, borderRadius: 8, marginVertical: 8 },
  btnText: { color: '#fff', fontWeight: '600' },
  or: { color: '#aaa', marginVertical: 8 },
  input: { width: '100%', backgroundColor: '#2a2a2a', color: '#fff', padding: 12, borderRadius: 8 },
});
