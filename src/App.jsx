
import { useState } from "react";
import { sendOTP, verifyOTP } from "./api";
import "./App.css";

function App() {
  const [aadhaar, setAadhaar] = useState("");
  const [otp, setOtp] = useState("");
  const [screen, setScreen] = useState("identity");

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [result, setResult] = useState("");

  // STEP 1: SEND OTP
  const handleSendOTP = async (e) => {
    e.preventDefault();

    if (!/^\d{12}$/.test(aadhaar)) {
      setMessage("Please enter a valid 12-digit Demo ID.");
      return;
    }

    setLoading(true);
    setMessage("");

    try {
      const response = await sendOTP(aadhaar);

      if (response.success &&
          response.data.result !== "FAILED" &&
          response.data.result !== "ERROR") {

        setScreen("otp");
        setMessage(
          response.data.message || "OTP request successful."
        );

      } else {
        setMessage(
          response.data.message || "Unable to send OTP."
        );
      }

    } catch (error) {
      setMessage("Unable to connect to authentication server.");
    }

    setLoading(false);
  };

  // STEP 2: VERIFY OTP
  const handleVerifyOTP = async (e) => {
    e.preventDefault();

    if (!/^\d{6}$/.test(otp)) {
      setMessage("Please enter a valid 6-digit OTP.");
      return;
    }

    setLoading(true);
    setMessage("");

    try {
      const response = await verifyOTP(aadhaar, otp);
      const data = response.data;

      if (
        data.result === "VERIFIED" ||
        data.result === "ALREADY_VERIFIED"
      ) {
        setResult(data.message);
        setScreen("success");

      } else {
        setMessage(data.message || "Verification failed.");
      }

    } catch (error) {
      setMessage("Unable to connect to authentication server.");
    }

    setLoading(false);
  };

  // RESET
  const handleReset = () => {
    setAadhaar("");
    setOtp("");
    setMessage("");
    setResult("");
    setScreen("identity");
  };

  return (
    <div className="app">

      <header className="navbar">
        <div className="logo">ID</div>
        <div>
          <h2>Digital Identity</h2>
          <p>Secure Demo Authentication Portal</p>
        </div>
      </header>

      <main className="container">

        <div className="auth-card">

          <div className="card-icon">
            {screen === "success" ? "✓" : "♙"}
          </div>

          {screen === "identity" && (
            <>
              <h1>Identity Verification</h1>
              <p className="subtitle">
                Enter your 12-digit demo identity number
                to receive a verification OTP.
              </p>

              <form onSubmit={handleSendOTP}>

                <label>Demo Identity Number</label>

                <input
                  type="text"
                  value={aadhaar}
                  onChange={(e) =>
                    setAadhaar(
                      e.target.value.replace(/\D/g, "").slice(0, 12)
                    )
                  }
                  placeholder="Enter 12-digit Demo ID"
                  maxLength="12"
                  required
                />

                <button disabled={loading}>
                  {loading ? "Sending OTP..." : "Send OTP"}
                </button>

              </form>
            </>
          )}

          {screen === "otp" && (
            <>
              <h1>OTP Verification</h1>

              <p className="subtitle">
                Enter the six-digit OTP generated
                for your demo identity.
              </p>

              <div className="masked-id">
                Demo ID: ******{aadhaar.slice(-4)}
              </div>

              <form onSubmit={handleVerifyOTP}>

                <label>Enter OTP</label>

                <input
                  type="text"
                  value={otp}
                  onChange={(e) =>
                    setOtp(
                      e.target.value.replace(/\D/g, "").slice(0, 6)
                    )
                  }
                  placeholder="Enter 6-digit OTP"
                  maxLength="6"
                  required
                />

                <button disabled={loading}>
                  {loading ? "Verifying..." : "Verify OTP"}
                </button>

              </form>

              <button
                className="secondary"
                onClick={handleReset}
                disabled={loading}
              >
                Back
              </button>
            </>
          )}

          {screen === "success" && (
            <>
              <h1>Verification Successful!</h1>

              <p className="subtitle">
                {result}
              </p>

              <div className="success-message">
                Your demo identity has been successfully verified.
              </div>

              <button onClick={handleReset}>
                New Authentication
              </button>
            </>
          )}

          {message && (
            <div className="message">
              {message}
            </div>
          )}

          <div className="security">
            <span>🔒</span>
            Secure Demo Authentication
          </div>

        </div>

      </main>

      <footer>
        <p>
          Academic Project | AWS Lambda | API Gateway | DynamoDB
        </p>
        <p>Demo system only — not an official UIDAI service.</p>
      </footer>

    </div>
  );
}

export default App;
