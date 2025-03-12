use serde::Serialize;

// Views:
//  * IntialView
//  * PromptView
//     * action: client sends credentials back to notary (action: login)
//  * PendingView
//     * action: notary might send status update (30/100) done
//     * action/gotoview: DoneView
//  * DoneView

pub enum Action {
  View(View), // can only be "sent" by Notary/ server
  Message(Payload),
  Close,
}

pub enum View {
  InitialView(InitialView),
  DoneView(DoneView),
}

pub struct Payload {}



pub struct InitialView {
  foo: String,
}

impl InitialView {
  pub fn into_done_view(&self) -> DoneView {

  }
}

pub struct DoneView {
  bar: String,
}

pub struct Session<V: ViewT> {
  current_view: V,
}

pub trait ViewT: Serialize {
  fn handle(&mut self, action: &Action) -> View;
}

impl ViewT for InitialView {
  fn handle(&mut self, action: &Action) -> View {
      match action {
        Action::View(_) => ..,

      }
  }
}


impl Session {
  pub fn handle(&mut self, input_json: &[u8]) -> Vec<u8> {
    // serde deseralize into Action::Message::Payload
    let action: Action = serde_json::from_slice(input_json);    

    let next_view = self.current_view.handle(action);

    return serde_json::to_vec(next_view);

    // match (self.current_view, action) {
    //   (View::InitialView(initial_view), Action::View(View::DoneView(_))) => {serde_json::to_vec(initial_view.into_done_view());},
    //   _ => Err("Invalid action given:\nAction:{:?}\nState:{:?}");
    // }

   let response = self.current_view.handle(action); 
   // TODO serialize response and then send to websocket connection
   // if response == Close -> close connection
  }
}



// impl Handler for InitialView {}



// pub struct Handler {
//   state: HandlerStates,
// }

// pub enum HandlerStates {}

// -----------------------------------
// pub struct View {}

// pub struct Response {}

// #[derive(Clone, Serialize)]
// pub struct Action {}

// pub enum Response {
//     GoToView(View),
//     Response(Action),
//     Close,
// }

// pub struct InitialView {
//   foobar: String,
//   state: String,
// }

// impl ViewT for InitialView {
//   fn handle(&mut self, action: &Action) -> Action {
//     match (action, self.state) {
//         (Action::Response::InitialView::DoSomethingCrazy(payload), "initial") => {
//         // do the crazy thing here
//         self.state = "crazythingcompleted"
//         return Action::Response(MyCrazyResult);
//       },

//       (Action::Response::InitialView::TheThingAfterTheCrazyCompute(payload),
// "crazythingcompleted") => {               return Action::Reponse(Error())
//       }
//     }

//     Action::GoToView(VIEW)
//   }
// }

// pub struct DoneView {
//   foobar: String,
// }

// impl ViewT for DoneView {
//   fn handle(&mut self, action: &Action) -> Action {
//     // match action {
//     //     // do the crazy thing here
//     //   },
//     // }

//     return Action::Close;
//   }
// }

// // json:
// // // {
// //   "action": {
// //     "type": "go_to_view",
// //     "data": {
// //       "foo": "bar"
// //     }
// //   }
// // }
// // {
// //   "action": {
// //     "type": "my_foobar_action",
// //     "data": {
// //       "foo": "bar"
// //     }
// //   }
// // }

// // -------------

// // #[derive(Clone, Serialize)]
// // pub struct Action {}

// // pub trait Response {}

// // pub struct Done {}
// // pub struct GotoView {}

// // pub enum ActionKind {
// //   GoToView(View),
// //   Response(Action),
// //   Close,
// // }

// // pub struct InitialView {
// //   foobar: String,
// // }

// // impl View for InitialView {
// //   fn handle(&mut self, action: &Action) -> impl Response {
// //     match action {
// //       Action::Response(_) => Done {},
// //       Action::GoToView(view) => GotoView {},
// //       Action::Close => Done {},
// //     }
// //   }
// // }
