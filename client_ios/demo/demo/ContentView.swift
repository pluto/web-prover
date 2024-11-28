//
//  ContentView.swift
//  test
//
//  Created by devloper on 9/30/24.
//

import SwiftUI
import Prover

class CustomURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let certificatePath = Bundle.main.path(forResource: "ca-cert", ofType: "cer"),
              let certificateData = try? Data(contentsOf: URL(fileURLWithPath: certificatePath)) else {
            print("Failed to load root CA certificate")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let rootCertificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            print("Failed to create SecCertificate")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        SecTrustSetAnchorCertificates(serverTrust, [rootCertificate] as CFArray)

        // Set a more lenient policy
        let policy = SecPolicyCreateBasicX509()
        SecTrustSetPolicies(serverTrust, policy)

        // Disable network fetching for revocation checks
        SecTrustSetNetworkFetchAllowed(serverTrust, false)

        var result: SecTrustResultType = .invalid
        if SecTrustEvaluate(serverTrust, &result) == errSecSuccess {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            print("Trust evaluation failed")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

func fetchData(from urlString: String, completion: @escaping (Data?, Error?) -> Void) {
    guard let url = URL(string: urlString) else {
        completion(nil, NSError(domain: "InvalidURL", code: 0, userInfo: nil))
        return
    }

    let delegate = CustomURLSessionDelegate()
    let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)

    let task = session.dataTask(with: url) { (data, response, error) in
        if let error = error {
            completion(nil, error)
            return
        }

        guard let data = data else {
            completion(nil, NSError(domain: "NoData", code: 0, userInfo: nil))
            return
        }

        completion(data, nil)
    }
    task.resume()
}

struct ContentView: View {

    var body: some View {

       VStack {
           Button("Call Setup Tracing") {
               Prover.setup_tracing()
           }
           .padding()
           .background(Color.blue)
           .foregroundColor(.white)
           .cornerRadius(10)

           Button("Call Prover Function") {
               let start = CFAbsoluteTimeGetCurrent()

               let localHost = "localhost"
               let localPort = "7443"
               let localAuthHeader = ""
               let localMethod = "GET"
               let localUrl = "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json"

               let circuit = "aes_gctr_nivc_512b.r1cs"
               let r1cs_url = "https://localhost:8090/build/target_512b/\(circuit)"

               // TODO: Live app should fetch these in parallel
               fetchData(from: r1cs_url) { (r1cs_data, error) in
                   if let error = error {
                       print("Error: \(error.localizedDescription)")
                       return
                   }

                   if let data = r1cs_data {
                       print("data: \(data)")
                       let arrayString = data.map { String($0) }.joined(separator: ",")

                       let jsonString = """
                        {
                            "max_recv_data": 10000,
                            "max_sent_data": 10000,
                            "mode": "Origo",
                            "notary_host": "\(localHost)",
                            "notary_port": \(localPort),
                            "target_body": "",
                            "target_headers": {
                                \(localAuthHeader)
                                "Content-Type": "application/json",
                                "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
                            },
                            "target_method": "\(localMethod)",
                            "target_url": "\(localUrl)",
                            "proving": {
                                "witnesses": [
                                    {
                                        "val": []
                                    }
                                ],
                                "manifest": {
                                    "manifestVersion": "1",
                                    "id": "reddit-user-karma",
                                    "title": "Total Reddit Karma",
                                    "description": "Generate a proof that you have a certain amount of karma",
                                    "prepareUrl": "https://www.reddit.com/login/",
                                    "request": {
                                        "method": "GET",
                                        "version": "HTTP/1.1",
                                        "url": "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
                                        "headers": {
                                            "accept-encoding": "identity"
                                        },
                                        "body": {
                                            "userId": "<% userId %>"
                                        },
                                        "vars": {
                                            "userId": {
                                                "regex": "[a-z]{,20}+"
                                            },
                                            "token": {
                                                "type": "base64",
                                                "length": 32
                                            }
                                        }
                                    },
                                    "response": {
                                        "status": "200",
                                        "version": "HTTP/1.1",
                                        "message": "OK",
                                        "headers": {
                                            "Content-Type": "application/json"
                                        },
                                        "body": {
                                            "json": [
                                                "data",
                                                "items",
                                                0
                                            ],
                                            "contains": "this_string_exists_in_body"
                                        }
                                    }
                                }
                            }
                        }
                        """

                       // NOTE: Witness generation happen in the library for ios
                       jsonString.withCString { (cString) in
                           Prover.prover(cString)
                       }
                       let timeElapsed = CFAbsoluteTimeGetCurrent() - start
                       print("Time elapsed: \(timeElapsed) seconds")
                   }
               }
           }
           .padding()
           .background(Color.blue)
           .foregroundColor(.white)
           .cornerRadius(10)
       }
   }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
