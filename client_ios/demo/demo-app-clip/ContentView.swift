//
//  ContentView.swift
//  test
//
//  Created by devloper on 9/30/24.
//

import SwiftUI
import Prover

struct ContentView: View {
    var body: some View {
  
       VStack {
           Button("Call Setup Tracing Function") {
               Prover.setup_tracing()
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
