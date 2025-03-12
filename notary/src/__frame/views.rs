// macro_rules! define_views {
//     ($(($variant:ident, $module:ident)),*) => {
//         // Define the modules
//         $(
//             pub mod $module;
//             pub use $module::$variant;
//         )*

//         pub enum View {
//             $($variant($variant)),*
//         }

//         impl View {
//             pub fn handle(&mut self) {
//                 // match self {
//                     // $(View::$variant(view) => view.handle()),*
//                 // }
//             }
//         }
//     }
// }

// define_views!(
//   (InitialView, initial_view),
//   (PendingView, pending_view),
//   (PromptView, prompt_view),
//   (DoneView, done_view)
// );

pub mod initial_view;
pub use initial_view::InitialView;

// pub mod pending_view;
// pub use pending_view::PendingView;

pub mod prompt_view;
pub use prompt_view::PromptView;

// pub mod done_view;
// pub use done_view::DoneView;

pub enum View {
  InitialView(InitialView),
  // PendingView(PendingView),
  // PromptView(PromptView),
  // DoneView(DoneView),
}

// impl View {
//   pub fn handle(&mut self) {
//     match self {
//       View::InitialView(view) => view.handle(),
//       View::PendingView(view) => view.handle(),
//       View::PromptView(view) => view.handle(),
//       View::DoneView(view) => view.handle(),
//     }
//   }

//   pub fn serialize(self) {
//     match self {
//       View::InitialView(view) => view.serialize(),
//       View::PendingView(view) => view.serialize(),
//       View::PromptView(view) => view.serialize(),
//       View::DoneView(view) => view.serialize(),
//     }
//   }
// }
