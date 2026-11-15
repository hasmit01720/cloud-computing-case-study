
const API_URLS = {
  sendOTP: "https://h45c08afaa.execute-api.ap-south-1.amazonaws.com/send-otp",
  verifyOTP:
    "https://h45c08afaa.execute-api.ap-south-1.amazonaws.com/verify-otp",
};

export async function sendOTP(aadhaarNo) {
  const response = await fetch(API_URLS.sendOTP, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      Aadharno: aadhaarNo,
    }),
  });

  const data = await response.json();

  return {
    status: response.status,
    success: response.ok,
    data,
  };
}

export async function verifyOTP(aadhaarNo, otp) {
  const response = await fetch(API_URLS.verifyOTP, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      Aadharno: aadhaarNo,
      otp: otp,
    }),
  });

  const data = await response.json();

  return {
    status: response.status,
    success: response.ok,
    data,
  };
}
